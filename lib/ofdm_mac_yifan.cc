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

class ofdm_mac_impl : public ofdm_mac {

	public:

	ofdm_mac_impl(
					bool debug, 
				) :
			block("ofdm_mac",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
			d_seq_nr(0) {

		d_debug = debug;
		// d_my_mac = MAC_Address(MACAddress);
		// d_default_dest_mac = MAC_Address("00:00:00:00:00:01");

		message_port_register_out(pmt::mp("phy out"));
		message_port_register_out(pmt::mp("app out"));

		message_port_register_in(pmt::mp("app in"));
		set_msg_handler(pmt::mp("app in"), boost::bind(&ofdm_mac_impl::app_in, this, _1));

		message_port_register_in(pmt::mp("cca in"));
		set_msg_handler(
			pmt::mp("cca in"), 
			boost::bind(&ofdm_mac_impl::cca_in, this, _1)
		);

		message_port_register_in(pmt::mp("phy in"));
		set_msg_handler(pmt::mp("phy in"), boost::bind(&ofdm_mac_impl::phy_in, this, _1));

		d_thread = boost::shared_ptr<boost::thread> 
			(new boost::thread(boost::bind(&ofdm_mac_impl::run, this)));

	}

	~ofdm_mac_impl(){
		//terminate the thread
		d_finished = true;
		d_thread -> interrupt();
		//wait until the thread stops
		d_thread -> join();
	}

	void phy_in (pmt::pmt_t msg) {
		std::string str;
		std::cout << "Received from PHY_IN: " << std::endl;
		if(pmt::is_blob(msg)){
			IEEE802_11_Frame frame;
			frame.from_msg(msg);
			this->d_phyin_buffer.push(frame);
			if(true){
				std::cout << "Received from PHY_IN: " << 
					frame.get_frame_type_string() << std::endl;
			}
		}
		
		// message_port_pub(pmt::mp("app out"), msg);
	}

	void cca_in(pmt::pmt_t msg){
		if(pmt::is_symbol(msg)){
			//do cca process;
		}
	}

	void app_in (pmt::pmt_t msg) {
		std::string str;
		if(pmt::is_eof_object(msg)){
			std::cout << "pmt::is_eof_file(msg) true" << std::endl;
		}else if(pmt::is_symbol(msg)){
			str = pmt::symbol_to_string(msg);
			d_appin_buffer.push(str);
			if(d_debug){
				std::cout << "Received from APP_IN: " << str << std::endl;
			}
		}
	}


	private:
		uint16_t d_seq_nr;
		char d_mac1[6];
		char d_mac2[6];
		char d_mac3[6];

		uint8_t d_my_mac;
		uint8_t d_default_dest_mac;

		
		//if the block is in debug mode. 
		bool d_debug = true;
		//state of the state machine
		int d_state = 0;

		
		//The thread 
		boost::shared_ptr<boost::thread> d_thread;
		//When the application down, destructor set it true and the thread stops
		bool d_finished = false;

		//Tow buffers that stores data from phy_in and app_in port
		//std::queue provide methods like empty, size, front, back, push,  pop, 
		std::queue<std::string> d_phyin_buffer;
		std::queue<std::string> d_appin_buffer;

		//NAV timer
		int d_nav_timer = 0;
		int d_backoff_timer = 0;
		int d_default_sifs = 0.5;
		int d_default_difs = 2.5;
		int d_ifs_timer = 0;

		//If channel occupied. The CCA_in will keep update it.
		bool d_channel_occupied = false;	
		int d_n_tx_attempts = 0;

		//If MAC is waiting for ACK,
		//if is waiting for ACK, sending is locked.
		bool d_waiting_for_ack = false;
		int d_ack_time_out = 0;


		
		//time slot length
		long d_timeslot_us_as_long = 1000000;
		boost::posix_time::time_duration d_timeslot_us = 
			boost::posix_time::microseconds( d_timeslot_us_as_long );
		boost::posix_time::ptime d_slotstart_us;
		boost::posix_time::ptime d_processend_us;



	/**
	* Serves as a timer to enter the state machine function
	*/
	void run(){
		while(!d_finished){
			//record the slot start time
			d_slotstart_us = boost::posix_time::microsec_clock::local_time();
			if(d_debug){
				std::cout << "Slot start at: " << d_slotstart_us << std::endl;
			}
			
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

			if(d_debug){
				std::cout << "Time remaining: " << time_to_sleep_us << std::endl;
			}
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
			std::cout << "PHY_IN buffer size: " << 
				d_phyin_buffer.size() << std::endl;
			std::cout << "APP_IN buffer size: " << 
				d_appin_buffer.size() << std::endl;
			std::cout << "In state " << mac_state_string[d_state] << std::endl;
		}
		switch(this->d_state){
		case IDLE: //IDLE
			process_phyin_buffer();
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
				d_n_tx_attempts++;
				d_backoff_timer = this->set_backoff_timer(d_n_tx_attempts);
				//go to IDLE
				switch_state(IDLE);
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
			IEEE802_11_Frame frame;
			frame = 
				IEEE802_11_Frame::generate_mac_data_frame(
					d_default_dest_mac,
					d_my_mac,
					d_appin_buffer.front().c_str(),
					d_appin_buffer.front().length(),
					0x2e,
					d_seq_nr
				);
			transmit_frame(frame);
			d_waiting_for_ack = true;
			d_ack_time_out = d_default_sifs;
			switch_state(WAIT_FOR_ACK);
			break;
		}
		case WAIT_FOR_ACK:
			process_phyin_buffer();
			if(d_waiting_for_ack==false){
				//I received the ack
				d_waiting_for_ack = false;
				d_ack_time_out = 0;
				switch_state(IDLE);
			}else{
				d_ack_time_out--;
				if(d_ack_time_out<0){
					//fail to receive ack
					d_waiting_for_ack = false;
					switch_state(IDLE);
				}
			}
			break;
		case SEND_ACK:

			break;
		}
		
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

	void process_phyin_buffer(){
		while(d_phyin_buffer.size()>0){
			IEEE802_11_Frame frame = d_phyin_buffer.front();
			switch(frame.get_type()){
			case IEEE802_11_Frame::BEACON:
				process_beacon(frame);
			case IEEE802_11_Frame::ACK:
				process_ack(frame);
			case IEEE802_11_Frame::DATA:
				process_data(frame);
				break;
			}
			
		}

	}

	void process_beacon(IEEE802_11_Frame frame){

	}

	void process_data(IEEE802_11_Frame frame){
		if(d_debug){
			std::cout << "Processing data" << std::endl;
		}
		MAC_Address from = frame.get_addr1();
		//1. pass the frame to upper layer;
		message_port_pub(pmt::mp("app out"), frame.get_msg());
		//2. send ACK;
		sleep_part_of_timeslot(d_default_sifs);

		IEEE802_11_Frame ackframe = 
			IEEE802_11_Frame::generate_mac_ack_frame(
				from,
				d_my_mac,
				0x2e,
				d_seq_nr
			);
		transmit_frame(ackframe);

	}

	void process_ack(IEEE802_11_Frame frame){
		if(d_debug){
			std::cout << "Processing ack" << std::endl;
		}
		MAC_Address dest = frame.get_addr1();
		if(d_my_mac.equals(dest)){
			d_waiting_for_ack = false;
		}
	}

	/**
	* Fetches one packet from the phy_in port, and returns it. 
	* Return NULL is appin_buffer is empty 
	*/
	bool read_from_phy(){
		if(d_phyin_buffer.size()>0){
			return true;
		}
		return false;
	}

	/**
	* Fetches one packet from the app_in port, and returns it. 
	* Return NULL is appin_buffer is empty 
	*/
	bool read_from_app(){
		if(d_appin_buffer.size()>0){
			// std::string str = d_appin_buffer.front();
			return true;
		}
		return false;
	}

	void transmit_frame(IEEE802_11_Frame frame){
		pmt::pmt_t dict = pmt::make_dict();
		dict = pmt::dict_add(dict, pmt::mp("crc_included"), pmt::PMT_T);

		// blob
		pmt::pmt_t mac = pmt::make_blob(
			frame.get_psdu(), 
			frame.get_psdu_size()
		);

		// pdu
		message_port_pub(pmt::mp("phy out"), pmt::cons(dict, mac));
	}



};

ofdm_mac::sptr
ofdm_mac::make(
		bool debug,
		std::string MACAddress
	) {
	return gnuradio::get_initial_sptr(
		new ofdm_mac_impl(
			debug
		)
	);
}

