/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <ieee802-11/ofdm_mac.h>

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include "utils.h"

#include <endian.h>

#include <boost/crc.hpp>
#include <iostream>
#include <stdexcept>
#include <time.h>
#include <queue>

using namespace gr::ieee802_11;

enum mac_state{
	IDLE,
	WAIT_FOR_NAV,
	WAIT_FOR_DIFS,
	BACKING_OFF,
	TRANSMIT_UNICAST,
	WAIT_FOR_ACK,
	SEND_ACK
};

static const int max_retries=7;

class ofdm_mac_impl : public ofdm_mac {

public:

ofdm_mac_impl(bool debug) :
		block("ofdm_mac",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(0, 0, 0)),
		d_seq_nr(0),
		d_state(0),
		d_finished(false),
		d_nav_timer(0),
		d_backoff_timer(0),
		d_default_sifs(0.5),
		d_default_difs(2.5),
		d_ifs_timer(0),
		d_channel_occupied(false),
		d_n_tx_attempts(0),
		d_waiting_for_ack(false),
		d_ack_time_out(false),
		d_timeslot_us_as_long(100000)
{
	d_debug=debug;
	d_timeslot_us=boost::posix_time::microseconds( d_timeslot_us_as_long );
	d_disable_mac_address_check = true;


	message_port_register_out(pmt::mp("phy out"));
	message_port_register_out(pmt::mp("app out"));

	message_port_register_in(pmt::mp("app in"));
	set_msg_handler(pmt::mp("app in"), boost::bind(&ofdm_mac_impl::app_in, this, _1));

	message_port_register_in(pmt::mp("phy in"));
	set_msg_handler(pmt::mp("phy in"), boost::bind(&ofdm_mac_impl::phy_in, this, _1));

	message_port_register_in(pmt::mp("cca in"));
	set_msg_handler(
		pmt::mp("cca in"),
		boost::bind(&ofdm_mac_impl::cca_in, this, _1)
	);

	d_thread = boost::shared_ptr<boost::thread>
		(new boost::thread(boost::bind(&ofdm_mac_impl::run, this)));

	// fix the destination mac for now
	d_mac[0]=0x00;
	d_mac[1]=0x00;
	d_mac[2]=0x00;
	d_mac[3]=0x00;
	d_mac[4]=0x00;
	d_mac[5]=0x00;
}

~ofdm_mac_impl(){
	//terminate the thread
	d_finished = true;
	d_thread -> interrupt();
	//wait until the thread stops
	d_thread -> join();
}

void cca_in(pmt::pmt_t msg){
	if(pmt::is_bool(msg))
		d_channel_occupied=pmt::to_bool(msg);
}


void phy_in (pmt::pmt_t msg) {
	parse(msg);
}

void app_in (pmt::pmt_t msg) {

	size_t       msg_len;
	const char   *msdu;

	if(pmt::is_eof_object(msg)) {
		message_port_pub(pmt::mp("phy out"), pmt::PMT_EOF);
		detail().get()->set_done(true);
		return;

	} else if(pmt::is_symbol(msg)) {

		std::string  str;
		str = pmt::symbol_to_string(msg);
		msg_len = str.length();
		msdu = str.data();

	} else if(pmt::is_pair(msg)) {
		size_t mac_len=6;
		const uint8_t *mac = pmt::u8vector_elements(pmt::car(msg),mac_len);
		set_d_mac(mac);
		msg_len = pmt::blob_length(pmt::cdr(msg));
		msdu = reinterpret_cast<const char *>(pmt::blob_data(pmt::cdr(msg)));

	} else {
		throw std::invalid_argument("OFDM MAC expects PDUs or strings");
                return;
	}
	std::string s(msdu,msg_len);
	d_appin_buffer.push(s); // be dealt with in the mac state machine
	if(d_debug){
		std::cout << "Received from APP_IN: " << s << std::endl;
	}

}


void parse(pmt::pmt_t msg) {

	if(pmt::is_eof_object(msg)) {
		detail().get()->set_done(true);
		return;
	} else if(pmt::is_symbol(msg)) {
		return;
	}

	msg = pmt::cdr(msg);

	int data_len = pmt::blob_length(msg);
	framectrl *frame_control = (framectrl *)pmt::blob_data(msg);


	//switch((frame_control >> 2) & 3) {
	switch(frame_control->type) {
	case 0:  // MANAGEMENT
		if (frame_control->subtype==8){  // beacon recvd

			// assert that msg length matches the beacon frame.
			if (data_len < 32)
			{
				return;
			}
			// process beacon
			char *frame = (char*)pmt::blob_data(msg);
			beacon_body *bb = (beacon_body *)(frame+24);
			stime = bb->timestamp;

		}
		break;
	case 1:  //CONTROL
		if (frame_control->subtype == 11){ // RTS
			rts_header *h = (rts_header*)pmt::blob_data(msg);
			if (is_my_mac(h->addr1,6,my_mac,6))  //send cts if RTS is for me
			{
				int    psdu_length;
				char   *psdu;

				generate_mac_cts_frame(h->addr2,h->duration-rts_time-SIFS,&psdu,&psdu_length);

				transmit_frame(psdu,psdu_length);

				free(psdu);
			}
		}else if (frame_control->subtype ==12){ // CTS
			// send data
			ack_header *h = (ack_header*)pmt::blob_data(msg);
			if (is_my_mac(h->addr,6,my_mac,6))  //send data packet if the recvd CTS is for the RTS I just sent
			{
				// make MAC frame for HOL packet and send
				int    psdu_length;
				char   *psdu;
				generate_mac_data_frame(d_mac, hol, hol_len, h->duration-cts_time-SIFS, &psdu, &psdu_length);

				transmit_frame(psdu,psdu_length);
				free(psdu);
			}
		}else if (frame_control->subtype ==13){ // ACK
			ack_header *h = (ack_header*)pmt::blob_data(msg);
			if (is_my_mac(h->addr,6,my_mac,6))  //my packet was acked
			{
				// send the next packet
				if (this->d_state == WAIT_FOR_ACK){
					d_waiting_for_ack=false;
					if(d_debug){
						std::cout << "ACK received" << std::endl;
					}
				}else
					std::cout << "ACK recvd after timeout! you may increase the timeout value." << std::endl;
			}
		}
		break;

	case 2:  //DATA
		if(frame_control->subtype == 0 || frame_control->subtype == 8) {
			mac_header *h = (mac_header*)pmt::blob_data(msg);
			if (is_my_mac(h->addr1,6,my_mac,6))
			{
				// ACK the packet first
				int    psdu_size;
				char   *psdu;
				generate_mac_ack_frame(h->addr2, 0, &psdu, &psdu_size);
				transmit_frame(psdu,psdu_size);
				free(psdu);

				// this could be outside of the if block to send the msg to ethernet no matter where it's destined to, but I chose not to at this time
				message_port_pub(pmt::mp("app out"), msg);
			}
		}
		break;

	default:
		break;
	}


}

void generate_mac_data_frame(const uint8_t *da, const char *msdu, int msdu_size, int duration, char **psdu, int *psdu_size) {

	// mac header
	mac_header header;
	header.frame_control = 0x0008;
	header.duration = duration;//0x002e;
	// Destination Address
	header.addr1[0] = *da;
	header.addr1[1] = *(da+1);
	header.addr1[2] = *(da+2);
	header.addr1[3] = *(da+3);
	header.addr1[4] = *(da+4);
	header.addr1[5] = *(da+5);
	// Source (My) Address
	header.addr2[0] = my_mac[0];
	header.addr2[1] = my_mac[1];
	header.addr2[2] = my_mac[2];
	header.addr2[3] = my_mac[3];
	header.addr2[4] = my_mac[4];
	header.addr2[5] = my_mac[5];

	header.addr3[0] = 0x42;
	header.addr3[1] = 0x42;
	header.addr3[2] = 0x42;
	header.addr3[3] = 0x42;
	header.addr3[4] = 0x42;
	header.addr3[5] = 0x42;

	header.seq_nr = 0;
	for (int i = 0; i < 12; i++) {
		if(d_seq_nr & (1 << i)) {
			header.seq_nr |=  (1 << (i + 4));
		}
	}
	header.seq_nr = htole16(header.seq_nr);
	d_seq_nr++;

	//header size is 24, plus 4 for FCS means 28 bytes
	*psdu_size = 28 + msdu_size;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy mac header into psdu
	std::memcpy(*psdu, &header, 24);
	//copy msdu into psdu
	memcpy(*psdu + 24, msdu, msdu_size);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, msdu_size + 24);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + msdu_size + 24, &fcs, sizeof(unsigned int));
}

void generate_mac_data_retx_frame(const uint8_t *da, const char *msdu, int msdu_size, int duration, char **psdu, int *psdu_size) {

	// mac header
	mac_header header;
	header.frame_control = 0x0808;
	header.duration = duration;//0x002e;
	// Destination Address
	header.addr1[0] = *da;
	header.addr1[1] = *(da+1);
	header.addr1[2] = *(da+2);
	header.addr1[3] = *(da+3);
	header.addr1[4] = *(da+4);
	header.addr1[5] = *(da+5);
	// Source (My) Address
	header.addr2[0] = my_mac[0];
	header.addr2[1] = my_mac[1];
	header.addr2[2] = my_mac[2];
	header.addr2[3] = my_mac[3];
	header.addr2[4] = my_mac[4];
	header.addr2[5] = my_mac[5];

	header.addr3[0] = 0x42;
	header.addr3[1] = 0x42;
	header.addr3[2] = 0x42;
	header.addr3[3] = 0x42;
	header.addr3[4] = 0x42;
	header.addr3[5] = 0x42;

	header.seq_nr = 0;
	for (int i = 0; i < 12; i++) {
		if(d_seq_nr & (1 << i)) {
			header.seq_nr |=  (1 << (i + 4));
		}
	}
	header.seq_nr = htole16(header.seq_nr);
	d_seq_nr++;

	//header size is 24, plus 4 for FCS means 28 bytes
	*psdu_size = 28 + msdu_size;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy mac header into psdu
	std::memcpy(*psdu, &header, 24);
	//copy msdu into psdu
	memcpy(*psdu + 24, msdu, msdu_size);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, msdu_size + 24);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + msdu_size + 24, &fcs, sizeof(unsigned int));
}


void generate_mac_beacon_frame(int duration, char **psdu, int *psdu_size) {

	// Beacon header
	mac_header header;
	header.frame_control = 0x0080;
	header.duration = duration;
	// Destination Address
	header.addr1[0] = 0xff;
	header.addr1[1] = 0xff;
	header.addr1[2] = 0xff;
	header.addr1[3] = 0xff;
	header.addr1[4] = 0xff;
	header.addr1[5] = 0xff;
	// Source (My) Address
	header.addr2[0] = my_mac[0];
	header.addr2[1] = my_mac[1];
	header.addr2[2] = my_mac[2];
	header.addr2[3] = my_mac[3];
	header.addr2[4] = my_mac[4];
	header.addr2[5] = my_mac[5];

	header.addr3[0] = 0x42;
	header.addr3[1] = 0x42;
	header.addr3[2] = 0x42;
	header.addr3[3] = 0x42;
	header.addr3[4] = 0x42;
	header.addr3[5] = 0x42;

	header.seq_nr = 0;
	for (int i = 0; i < 12; i++) {
		if(d_seq_nr & (1 << i)) {
			header.seq_nr |=  (1 << (i + 4));
		}
	}
	header.seq_nr = htole16(header.seq_nr);
	d_seq_nr++;

	beacon_body *body;
	body->timestamp=(uint32_t)time(NULL);  // may be needed to be replaced by stime if it's not 0
	body->interval=1000;  // 1024000usec, 1e3 Kusec, 1Kusec=1024usec
	body->capability_info=0x2; // second bit is set to indicate an IBSS (Adhoc)
	int bodysize=8;
	//header size is 24, plus 4 for FCS means 28 bytes
	*psdu_size = 28 + bodysize;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy mac header into psdu
	std::memcpy(*psdu, &header, 24);
	//copy msdu into psdu
	memcpy(*psdu + 24, body, bodysize);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, bodysize + 24);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + bodysize + 24, &fcs, sizeof(unsigned int));
}

void generate_mac_ack_frame(const uint8_t *ra, int duration, char **psdu, int *psdu_size) {

	// ACK header

	ack_header header;
	header.frame_control = 0x00d4;
	header.duration = duration;
	// Destination Address
	header.addr[0] = *ra;
	header.addr[1] = *(ra+1);
	header.addr[2] = *(ra+2);
	header.addr[3] = *(ra+3);
	header.addr[4] = *(ra+4);
	header.addr[5] = *(ra+5);


	//header size is 10, plus 4 for FCS means 14 bytes
	*psdu_size = 14;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy qck header into psdu
	std::memcpy(*psdu, &header, 10);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, 10);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + 10, &fcs, sizeof(unsigned int));
}

void generate_mac_rts_frame(const uint8_t *ra, int duration, char **psdu, int *psdu_size) {

	// RTS header

	rts_header header;
	header.frame_control = 0x00b4;
	header.duration = duration;

	// Destination Address
	header.addr1[0] = *ra;
	header.addr1[1] = *(ra+1);
	header.addr1[2] = *(ra+2);
	header.addr1[3] = *(ra+3);
	header.addr1[4] = *(ra+4);
	header.addr1[5] = *(ra+5);

	header.addr2[0] = my_mac[0];
	header.addr2[1] = my_mac[1];
	header.addr2[2] = my_mac[2];
	header.addr2[3] = my_mac[3];
	header.addr2[4] = my_mac[4];
	header.addr2[5] = my_mac[5];

	//header size is 16, plus 4 for FCS means 20 bytes
	*psdu_size = 20;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy qck header into psdu
	std::memcpy(*psdu, &header, 16);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, 16);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + 16, &fcs, sizeof(unsigned int));
}

void generate_mac_cts_frame(const uint8_t *ra, int duration, char **psdu, int *psdu_size) {

	// CTS header (same as ACK header)

	ack_header header;
	header.frame_control = 0x00d4;
	header.duration = duration;
	// Destination Address
	header.addr[0] = *ra;
	header.addr[1] = *(ra+1);
	header.addr[2] = *(ra+2);
	header.addr[3] = *(ra+3);
	header.addr[4] = *(ra+4);
	header.addr[5] = *(ra+5);


	//header size is 10, plus 4 for FCS means 14 bytes
	*psdu_size = 14;
	*psdu = (char *) calloc(*psdu_size, sizeof(char));

	//copy qck header into psdu
	std::memcpy(*psdu, &header, 10);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(*psdu, 10);

	unsigned int fcs = result.checksum();
	memcpy(*psdu + 10, &fcs, sizeof(unsigned int));
}

bool is_my_mac(uint8_t *mac1, int mac1_size, uint8_t *mac2, int mac2_size)
{
	if(d_disable_mac_address_check){
		return true;
	}
	if (mac1_size != mac2_size)
		return false;
	if (mac1_size != 6)
		std::cout << "mac address type inputs are expected!" << std::endl;
		return false;
	int i;
	for (i=0;i<6;i++)
	{
		if (mac1[i] != mac2[i])
			return false;
	}
	return true;

}

void set_d_mac(const uint8_t * mac)
{
	int i;
	for (i=0;i<6;i++)
	{
		d_mac[i] = mac[i];
	}
}
/**
* Serves as a timer to enter the state machine function
*/
void run(){
	while(!d_finished){
		//record the slot start time
		d_slotstart_us = boost::posix_time::microsec_clock::local_time();
		// if(d_debug){
		// 	std::cout << "Slot start at: " << d_slotstart_us << std::endl;
		// }

		//update the state machine,
		this->tick();

		//record the processing finish time
		d_processend_us = boost::posix_time::microsec_clock::local_time();
		//calculate the remaining time of the time slot,
		boost::posix_time::time_duration time_to_sleep_us =
			d_timeslot_us-( d_processend_us - d_slotstart_us );

		if(time_to_sleep_us.is_negative()){
			std::cerr <<
				"Overrun in MAC layer, time slot is not long enough"
				<< std::endl;
			exit(0);
		}

		// if(d_debug){
		// 	std::cout << "Time remaining: " << time_to_sleep_us << std::endl;
		// }
		//sleep during the remaining time
		boost::this_thread::sleep(
			time_to_sleep_us
		);
	}
	if(d_debug){
		std::cout << "Thread terminated." << std::endl;
	}
}



void sleep_part_of_timeslot(float persent){
	if(persent>1 || persent<0){
		std::cerr << __FUNCTION__ << " Can not sleep for "
			<< persent << " time slot \n";
		exit(1);
	}else{
		boost::posix_time::time_duration to_sleep =
			boost::posix_time::microseconds(
				persent*d_timeslot_us_as_long
			);
		boost::this_thread::sleep(
			to_sleep
		);

	}
}


/**
* Updates the state machine and do corresponding action
*/
void tick(){
	if(d_debug){
		//std::cout << "PHY_IN buffer size: " <<
		//	d_phyin_buffer.size() << std::endl;
		std::cout << "APP_IN buffer size: " <<
			d_appin_buffer.size() << std::endl;
		//std::cout << "In state " << mac_state_string[d_state] << std::endl;
	}

	switch(this->d_state){
	case IDLE: //IDLE
		//process_phyin_buffer();
		if(d_state == IDLE){
			//if state does not switch, process_appin_buffer
			if(read_from_app()){
				if(d_nav_timer>=0){
					//go to WAIT_FOR_NAV
					switch_state(WAIT_FOR_NAV);
				}else if(d_backoff_timer>=0){
					//backoff is required, go to backoff directly
					switch_state(BACKING_OFF);
				}else{
					//go to WAIT_FOR_DIFS
					switch_state(WAIT_FOR_DIFS);
				}
			}
		}

		break;
	case WAIT_FOR_NAV: //WAIT_FOR_NAV
		this->d_nav_timer--;
		if(d_nav_timer<0){
			d_nav_timer = 0;
			//go to WAIT_FOR_DIFS
			d_ifs_timer = d_default_difs;
			switch_state(WAIT_FOR_DIFS);
		}
		break;
	case WAIT_FOR_DIFS: //WAIT_FOR_DIFS
		if(this->d_channel_occupied){
			//TX attempts failed,
			//Set backoff timer and go to IDLE
			d_n_tx_attempts++;                                                     // I am not sure whether this is supposed to happen
			switch_state(IDLE);
			if (packet_drop(d_n_tx_attempts))
				break;
			d_backoff_timer = this->set_backoff_timer(d_n_tx_attempts);
			//go to IDLE
		}else{
			d_ifs_timer--;
			if(d_ifs_timer<=0){
				d_ifs_timer = 0;
				d_backoff_timer = this->set_backoff_timer(d_n_tx_attempts);
				switch_state(BACKING_OFF);
			}
		}
		break;
	case BACKING_OFF: //BACKING_OFF
		if(d_debug){
			std::cout << "Backoff timer remaining: " <<
				d_backoff_timer << std::endl;
		}
		if(this->d_channel_occupied){
			//channel busy during backing off.
			//go to IDLE
			switch_state(IDLE);
		}else{
			d_backoff_timer--;
			if(d_backoff_timer<0){
				d_backoff_timer = 0;
				//backoff end, transmit
				switch_state(TRANSMIT_UNICAST);
			}
		}
		break;
	case TRANSMIT_UNICAST:
	{

		// make MAC frame
		int    psdu_length;
		char   *psdu;
		// FIXME: duration must be calculated based on channel rate
		generate_mac_data_frame(d_mac,d_appin_buffer.front().c_str(), d_appin_buffer.front().length(), 0x2e, &psdu, &psdu_length);

		transmit_frame(psdu,psdu_length);

		free(psdu);


		d_waiting_for_ack = true;
		d_ack_time_out = d_default_sifs;
		switch_state(WAIT_FOR_ACK);
		break;
	}
	case WAIT_FOR_ACK:
		//process_phyin_buffer();
		if(!d_waiting_for_ack){
			//I received the ack
			d_waiting_for_ack = false;
			d_ack_time_out = 0;
			switch_state(IDLE);
		}else{
			d_ack_time_out--;
			if(d_ack_time_out<0){
				//fail to receive ack

				// retransmit if cap hasn't reached
				d_n_tx_attempts++;
				packet_drop(d_n_tx_attempts);
				d_waiting_for_ack = false;
				switch_state(IDLE);
			}
		}
		break;
	case SEND_ACK:
		break;
	}

}

void switch_state(short int a)
{
	d_state=a;
}
/**
* Updates the Backoff timer based on the time of failure transmission
*/
int set_backoff_timer(int tx_attempts){
	int cw_min = 15;
	int cw_max = 0;
	int cw = 0;
	if(tx_attempts==1){
		return cw_min;
	}else{
		cw_max = cw_min * ( 2*(tx_attempts-1) );
		if( cw_max > 1023 ){
			cw_max = 1023;
		}
		cw = rand()%(cw_max-cw_min)+cw_min;
		return cw;
	}
	return cw;
}

void transmit_frame(char *psdu, int psdu_length){

	// dict
	pmt::pmt_t dict = pmt::make_dict();
	dict = pmt::dict_add(dict, pmt::mp("crc_included"), pmt::PMT_T);

	// blob
	pmt::pmt_t mac = pmt::make_blob(psdu, psdu_length);

	// pdu
	message_port_pub(pmt::mp("phy out"), pmt::cons(dict, mac));
}

bool read_from_app(){
	if(d_appin_buffer.size()>0){
		// std::string str = d_appin_buffer.front();
		return true;
	}
	return false;
}

bool packet_drop(int n_tx_attempt)
{
	if (n_tx_attempt==max_retries)
	{
		d_appin_buffer.front(); // pop packet out of the queue
		d_n_tx_attempts=0;
		//switch_state(IDLE);
		return true;
	}
	return false;

}

private:
	uint16_t d_seq_nr;
	uint8_t d_mac[6]; // HOL packet's dest
	uint8_t my_mac[6];
	uint8_t bs_mac[6];
	uint32_t stime; // synced time, sync when receive a beacon

	// timing values in usec
	int DIFS;
	int SIFS;
	int slotTime;
	int rts_time;
	int cts_time;
	int ack_time;


	// HOL Packet
	char *hol;
	int hol_len;

	//if the block is in debug mode.
	bool d_debug;
	//state of the state machine
	int d_state;


	//The thread
	boost::shared_ptr<boost::thread> d_thread;
	//When the application down, destructor set it true and the thread stops
	bool d_finished;

	//Tow buffers that stores data from phy_in and app_in port
	//std::queue provide methods like empty, size, front, back, push,  pop,
	std::queue<std::string> d_phyin_buffer;
	std::queue<std::string> d_appin_buffer;

	//NAV timer
	int d_nav_timer;
	int d_backoff_timer;
	int d_default_sifs;
	int d_default_difs;
	int d_ifs_timer;

	//If channel occupied. The CCA_in will keep update it.
	bool d_channel_occupied;
	int d_n_tx_attempts;

	//If MAC is waiting for ACK,
	//if is waiting for ACK, sending is locked.
	bool d_waiting_for_ack;
	int d_ack_time_out;

	bool d_disable_mac_address_check;



	//time slot length
	long d_timeslot_us_as_long;
	boost::posix_time::time_duration d_timeslot_us;
	boost::posix_time::ptime d_slotstart_us;
	boost::posix_time::ptime d_processend_us;

};


ofdm_mac::sptr
ofdm_mac::make(bool debug) {
	return gnuradio::get_initial_sptr(new ofdm_mac_impl(debug));
}

