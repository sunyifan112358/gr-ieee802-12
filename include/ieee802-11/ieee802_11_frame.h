#ifndef INCLUDED_IEEE802_11_FRAME_H
#define INCLUDED_IEEE802_11_FRAME_H
namespace gr {
namespace ieee802_11 {

struct mac_header {
	//protocol version, type, subtype, to_ds, from_ds, ...
	uint16_t frame_control;
	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
	uint8_t addr3[6];
	uint16_t seq_nr;
}__attribute__((packed));

struct framectrl {
	uint8_t  prot_ver  :2;
	uint8_t  type      :2;
	uint8_t  subtype   :4;
	uint8_t  toDS      :1;
	uint8_t  fromDS    :1;
	uint8_t  moreFrag  :1;
	uint8_t  retry     :1;
	uint8_t  pwrMgt    :1;
	uint8_t  moreData  :1;
	uint8_t  wep       :1;
	uint8_t  rsdv      :1;
}__attribute__((packed));

struct beacon_body {
	uint32_t timestamp;
	uint16_t interval;
	uint16_t capability_info;
}__attribute__((packed));


struct ack_header {
	uint16_t frame_control;
	uint16_t duration;
	uint8_t addr[6];
}__attribute__((packed));

struct rts_header {
	uint16_t frame_control;
	uint16_t duration;
	uint8_t addr1[6];
	uint8_t addr2[6];
}__attribute__((packed));

struct neighbor {
	uint8_t addr[6];
}__attribute__((packed));


class MAC_Address{
private:
	struct MAC{
		uint8_t addr[6];
	}__attribute__((packed));

	MAC mac;

public:
	MAC_Address();
	MAC_Address(std::string str);
	MAC_Address(uint8_t * p);

	bool equals(MAC_Address m2);

	uint8_t get(int i){
		if(i>6 || i<0){
			std::cerr << "Cannot get MAC Address [" << i << "]" <<std::endl;
			exit(1);
		}else{
			return mac.addr[i];
		}
	};
};

class IEEE802_11_Frame{
public:
	std::string frame_type_string [7] = {
		"BEACON",
		"RTS",
		"CTS",
		"ACK",
		"DATA",
		"NULLDATA",
		"OTHER"
	};
	enum frame_type{
		BEACON,
		RTS,
		CTS,
		ACK,
		DATA,
		NULLDATA,
		OTHER
	};
private:
	pmt::pmt_t msg;

	char *psdu;
	int psdu_size;

	mac_header * header;

	
	frame_type type = OTHER;

	MAC_Address addr1;
	MAC_Address addr2;
	MAC_Address addr3;

	void parse_frame_control(framectrl *frame_control);
	void parse_data_frame(pmt::pmt_t msg);
	void parse_ack_frame(pmt::pmt_t msg);

	
public:

	
	/**
	* Default constructor
	*/
	IEEE802_11_Frame(){}
	~IEEE802_11_Frame(){
		if(psdu!=NULL){
			free(psdu);
		}
	}
	void from_msg(pmt::pmt_t msg);

	pmt::pmt_t get_msg(){return this->msg;};
	
	IEEE802_11_Frame::frame_type get_type(){return this->type;}
	char * get_psdu(){return this->psdu;}
	int get_psdu_size(){return this->psdu_size;}
	MAC_Address get_addr1(){return this->addr1;}
	MAC_Address get_addr2(){return this->addr2;}
	MAC_Address get_addr3(){return this->addr3;}


	std::string get_frame_type_string(){return frame_type_string[type];}

	static IEEE802_11_Frame generate_general_frame(
		MAC_Address dest,
		MAC_Address from,
		const void* body,
		int body_size,
		uint16_t frame_control,
		int duration,
		int d_seq_nr
	);
	static IEEE802_11_Frame generate_mac_data_frame(
		MAC_Address dest,
		MAC_Address from,
		const char *msdu, 
		int msdu_size, 
		int duration,
		int d_seq_nr
	);

	static IEEE802_11_Frame generate_mac_data_retx_frame(
		MAC_Address dest, 
		MAC_Address from, 
		const char *msdu, 
		int msdu_size, 
		int duration, 
		int d_seq_nr
	);
	static IEEE802_11_Frame generate_mac_beacon_frame(
		MAC_Address my_mac,
		int duration, 
		int d_seq_nr
	);

	static IEEE802_11_Frame generate_mac_ack_frame(
		MAC_Address to,
		MAC_Address from, 
		int duration, 
		int d_seq_nr
	);
	static IEEE802_11_Frame generate_mac_rts_frame(
		MAC_Address to,
		MAC_Address from, 
		int duration,
		int d_seq_nr
	);
	static IEEE802_11_Frame generate_mac_cts_frame(
		MAC_Address to,
		MAC_Address from, 
		int duration,
		int d_seq_nr
	);

};

}
}
#endif