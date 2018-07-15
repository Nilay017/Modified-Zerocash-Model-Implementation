#include <breep/network/tcp.hpp>
#include <breep/util/serialization.hpp>
#include <iostream>
#include <ctime>
#include <bits/stdc++.h>
#include <unordered_set>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sstream>

BREEP_DECLARE_TYPE(std::string)

struct name {
	name() : name_() {}

	name(const std::string& val)
			: name_(val)
	{}

	std::string name_;

	BREEP_ENABLE_SERIALIZATION(name, name_)
};
BREEP_DECLARE_TYPE(name)



class chat_manager {
public:
        deque<string> unprocessed_data_trans;
        deque<string> unprocessed_data_block;

	chat_manager(const std::string& name)
			: m_name(name)
			, m_nicknames()
                        , recv_buffer()
                        , unprocessed_data_trans()
                        , unprocessed_data_block()
	{}

	void connection_event(breep::tcp::network& network, const breep::tcp::peer& peer) {
		if (peer.is_connected()) {
			network.send_object_to(peer, m_name);
		} else {
			std::cout << m_nicknames.at(peer.id()) << " disconnected." << std::endl;
		}
	}

	void name_received(breep::tcp::netdata_wrapper<name>& dw) {
		m_nicknames.insert(std::make_pair(dw.source.id(), dw.data.name_));
		std::cout << dw.data.name_ << " connected." << std::endl;
	}

	void message_received(breep::tcp::netdata_wrapper<std::string>& dw) {
		std::cout << m_nicknames.at(dw.source.id()) << ": " << dw.data << std::endl;
                size_t pos=0;
                string tmp_msg=dw.data;
                if((pos=tmp_msg.find("$"))!=string::npos)
                {
                  string tmp_msghash=tmp_msg.substr(0,pos);
                  string packet_id="";
                  tmp_msg.erase(0,pos+1);
                  if((pos=tmp_msg.find("$"))!=string::npos)
                  {
		            if(pos!=0)
		            {
		             packet_id=tmp_msg.substr(0,pos);
		            }
		            tmp_msg.erase(0,pos+1);
		            map<string, pair<long int, string> >::iterator itr01;
		            if(recv_buffer.find(tmp_msghash)!=recv_buffer.end())
		            {
		              itr01=recv_buffer.find(tmp_msg);
		              stringstream num((itr01->second).first);
		              long int pckid=0;
		              pckid << num;
				      if((packet_id=="")&&(pckid>-1))
				      {
				       (itr01->second).first=-1;
				       (itr01->second).second+=tmp_msg;
				       //Now verify the hash
				       string msg2=(itr01->second).second;
				       long int size2=msg2.length();
		  		       char buffer2[65];
		  		       char* buf22=new char[size2];
				       strcpy(buf22, msg2.c_str());
				       sha256(buf22, buffer2);
				       string msg_hash2(buffer2);
				       delete[] buf22;
				       if(msg_hash2!=tmp_msghash) recv_buffer.erase(tmp_msghash); //delete entry if hash doesnt verify
		                       else
		                       {
		                        //Add to unprocessed_data_*
                                        if(((itr01->second).second).substr(0,5)=="chain") 
                                        {unprocessed_data_block.push_back((itr01->second).second);}
                                        else if(((itr01->second).second).substr(0,5)=="trans")
                                        {
 					 unprocessed_data_trans.push_back((itr01->second).second);
                                        }
                                        else{}
		                       
		                        recv_buffer.erase(tmp_msghash);
		                       }
				      }
				      else if(pckid>-1)
				      {
				       stringstream num2(packet_id);
				       long int pcktid2=0;
				       pckid2 << num2;
				       if(pckid2==(pckid+1))
				       {
				        (itr01->second).first=pckid2;
				        (itr01->second).second+=tmp_msg;
				       }
				      }
				      else
				      {
		                       //Do nothing
				      }
		            }
		            else
		            {
			             if(packet_id=="")
		                     {
				       //Verify the hash first
		                       char buffer3[65];
		                       chr* buf33=new char[tmp_msg.length()];
		                       strcpy(buf33, tmp_msg.c_str());
		                       sha256(buf33, buffer3);
		                       string msg_hash3(buffer3);
                                       delete buf33[];
		                       if(msg_hash3==tmp_msghash)
                                       {
		                                if(((itr01->second).second).substr(0,5)=="chain") 
		                                {unprocessed_data_block.push_back((itr01->second).second);}
		                                else if(((itr01->second).second).substr(0,5)=="trans")
		                                {
	 					 unprocessed_data_trans.push_back((itr01->second).second);
		                                }
		                                else{}
                                       } //Add to unprocessed_data_* if valid
		                     }
		                     else
		                     {
		                       stringstream num3(packet_id);
		                       long int pckid3=0;
		                       pckid3 << num3;
		                       recv_buffer.insert(make_pair(tmp_msghash, make_pair(pckid3, tmp_msg)));
		                     }
		            }
                 }
       	      }              
	}


private:
	name m_name;
	std::unordered_map<boost::uuids::uuid, std::string,  boost::hash<boost::uuids::uuid>> m_nicknames;
        map<string, pair<long int, string> > recv_buffer;
};



void sha256(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}


/*
EVP_PKEY* should be of the type EVP_PKEY_EC only
The public key for Verification of signature should be of the same type
*/

unsigned char* Create_ECDSA_Signature(size_t* &slen, EVP_PKEY* key, const char* msg)
{
	EVP_MD_CTX *mdctx = NULL;
	int ret = 0;
	 
	unsigned char **sig=new unsigned char*;
        *sig=NULL;
	 
	/* Create the Message Digest Context */
	if(!(mdctx = EVP_MD_CTX_create())) return NULL;
	
	/* Initialise the DigestSign operation - SHA-256 has been selected as the message digest function*/
	 if(1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, key)) return NULL;
	 
	 /* Call update with the message */
	 if(1 != EVP_DigestSignUpdate(mdctx, msg, strlen(msg))) return NULL;
	
	 /* Finalise the DigestSign operation */
	 /* First call EVP_DigestSignFinal with a NULL sig parameter to obtain the length of the
	  * signature. Length is returned in slen */
   
	 if(1 != EVP_DigestSignFinal(mdctx, NULL, slen)) {cout<<"NOOOO"<<endl;return NULL;}
        
	 /* Allocate memory for the signature based on size in slen */
	 if(!(*sig = new unsigned char[sizeof(unsigned char) * (*slen)] )) return NULL;
	
         /* Obtain the signature */
	 if(1 != EVP_DigestSignFinal(mdctx, *sig, slen)) return NULL;
	
	 /* Success */
	 ret = 1;
	 
	 if(mdctx) EVP_MD_CTX_destroy(mdctx);
	
	 /* Clean up */
	 return *sig;	 
}

bool Verify_ECDSA_Signature(unsigned char* sig, size_t slen, const char* msg, EVP_PKEY* Pubkey)
{
	EVP_MD_CTX *mdctx = NULL;
        if(!(mdctx = EVP_MD_CTX_create())) return false;
	/* Initialize 'Pubkey' with a public key */

	if(1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, Pubkey)) return false;

	if(1 != EVP_DigestVerifyUpdate(mdctx, msg, strlen(msg))) return false;

	if(1 == EVP_DigestVerifyFinal(mdctx, sig, slen))
	{
            if(mdctx) EVP_MD_CTX_destroy(mdctx);
	    return true;
	}
   
       if(mdctx) EVP_MD_CTX_destroy(mdctx);
       return false;
	
}


bool Generate_params_key_ECDSA(EVP_PKEY*& params, EVP_PKEY*& key, EVP_PKEY_CTX*& pctx, EVP_PKEY_CTX*& kctx)
{  
    
  
  /* Create the context for generating the parameters */
  if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) return false;
  if(!EVP_PKEY_paramgen_init(pctx)) return false;
  //cout<<"NIC"<<endl;
  /* Set the paramgen parameters */
  /* Use the NID_X9_62_prime256v1 named curve - defined in obj_mac.h */

  if(!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) return false;		

  /* Generate parameters */
  if (!EVP_PKEY_paramgen(pctx, &params)) return false;


  if(params != NULL)
  {
    if(!(kctx = EVP_PKEY_CTX_new(params, NULL))) return false; 
  }
  else
  {
    /* Create context for the key generation */
    if(!(kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) return false;
  }

  if(!EVP_PKEY_keygen_init(kctx)) return false;

  /* Generate the key */
  if (!EVP_PKEY_keygen(kctx, &key)) return false;

  return true;
}


/*
Message data packet format : totalmsghash$packetno$data
totalmsghash is the unique identifier for large message packet stream
totalmsghash is the sha256 hash of the message reconstructed by appending all the data in correct order
data is of at most 3500 characters
Last Packet will be encapsulated as totalmsghash$$data
Message is accepted only if the hash verifies
*/

/*
Format of the transaction message string:

"trans-transid1|outfield1#transid2|outfield2#transid3|outfield3-pubkey1|amount#pubkey2|amount2-transfee-signature-payerpublickey"

String used for signing:
"trans-transid1|outfield1#transid2|outfield2#transid3|outfield3-pubkey1|amount#pubkey2|amount2-transfee"

Format of the string Signature:
asciinum1&asccinum2&asciinum3&.....asciinumN

Convert the asciinum(which is in int format) to unsigned char later for verification


*/ 


class Transaction
{
  public:

  string Transid; //Hash of transaction message string
  string payer_publickey;
  vector<pair<string,long long> > input_fields;
  vector<pair<string,long long> > output_fields;
  long long trans_fee;
  string Signature;

Transaction() : Transid(), payer_publickey(), input_fields(), output_fields(), trans_fee(0), Signature()
{}

Transaction(const Transaction &T)
{
  Transid=T.Transid;
  payer_publickey=T.payer_publickey;
  input_fields=T.input_fields;
  output_fields=T.output_fields;
  trans_fee=T.trans_fee;
  Signature=T.Signature;
}
  
Transaction(vector< pair<string, long long> > a, vector< pair<string, long long> > b, long long t, string sign, string pubkey)
  {
    input_fields=a;
    output_fields=b;
    trans_fee=t;
    Signature=sign;
    payer_publickey=pubkey;
    string buf=(*this).Convert_to_String();
    char buffer[65];
    char* buf2=new char[buf.length()];
    strcpy(buf2, buf.c_str());
    sha256(buf2, buffer);
    string sss(buffer);
    Transid=sss;
    delete[] buf2;
}


Transaction& operator=(const Transaction &T)
{
  payer_publickey=T.payer_publickey;
  input_fields=T.input_fields;
  output_fields=T.output_fields;
  trans_fee=T.trans_fee;
  Signature=T.Signature;
  Transid=T.Transid;
  return *this;
}

bool operator==(const Transaction &T)
const {
  return ((payer_publickey==T.payer_publickey)&&(input_fields==T.input_fields)&&(output_fields==T.output_fields)&&(trans_fee==T.trans_fee)&&(Signature==T.Signature)&&(Transid==T.Transid));
}


   bool resolve_fields(string fieldstr,int field_type)
  {
   string msg,msg2;
   size_t pos, pos2;
   string temp_1;
   long long temp_2;
   msg=fieldstr;
   stringstream convert;
   convert.str("");
   convert.clear();

   while((pos=msg.find("#"))!=std::string::npos)
     {
	msg2 = msg.substr(0,pos);
        
        if((pos2=msg2.find("|"))!=std::string::npos) convert << msg2.substr(0,pos2);
        else return false;
        convert >> temp_1;
        msg2.erase(0,pos2+1);
        convert.str("");
     	convert.clear();
        
        convert << msg2;
        convert >> temp_2;
        convert.str("");
        convert.clear();


        if(field_type==0) input_fields.push_back(pair<string, long long>(temp_1,temp_2));
        else output_fields.push_back(pair<string, long long>(temp_1,temp_2));

        msg.erase(0, pos+1);
     }

        msg2 = msg.substr(0,pos);
        
        if((pos2=msg2.find("|"))!=std::string::npos) convert << msg2.substr(0,pos2);
        else return false;  
        convert >> temp_1; 
        msg2.erase(0,pos2+1);     
        convert.str("");
        convert.clear();

        convert << msg2;
        convert >> temp_2;
        convert.str("");
        convert.clear();
        
	if(field_type==0) input_fields.push_back(pair<string, long long>(temp_1,temp_2));
        else output_fields.push_back(pair<string, long long>(temp_1,temp_2));

	return true;     
   }
      


  bool Extract_trans(string msg)
  {  
     vector<string> components;
     size_t pos=0;
     while((pos=msg.find("-"))!=std::string::npos)
     {
	components.push_back(msg.substr(0,pos));
        msg.erase(0, pos+1);
     }
     
     components.push_back(msg);
     if(components.size()!=6) return false;
     if(components[0]!="trans") return false;
     
     stringstream convert;
     bool a=(resolve_fields(components[1],0))&&(resolve_fields(components[2],1));
     if(!a) return false;

     convert << components[3];
     convert >> trans_fee;
     convert.str("");
     convert.clear();

      
     Signature=components[4];
     payer_publickey=components[5];

     string buf=(*this).Convert_to_String();
     char buffer[65];
     char* buf2=new char[buf.length()];
     strcpy(buf2, buf.c_str());
     sha256(buf2, buffer);
     string sss(buffer);
     Transid=sss;
     delete[] buf2;
     return true;
  }


string construct_io_fields(int field_type)
{
  vector<pair<string,long long> >* ref;
  string temp,out="";

  if(field_type==0) ref=&input_fields;
  else ref=&output_fields;

  long long size=ref->size();   
  for (long long i = 0; i < ref->size(); i++)
  {
   temp=(ref->at(i)).first+"|"+to_string((ref->at(i)).second);
   if(i!=(size-1)) temp+="#";
   out+=temp;
  }

  return out;
}


string Convert_to_String()
{
   string out="trans-"+construct_io_fields(0)+"-"+construct_io_fields(1)+"-"+to_string(trans_fee)+"-";
   out+=Signature;
   out+="-";
   out+=payer_publickey;
   return out;}


void clearfields()
{
  input_fields.resize(0);
  output_fields.resize(0);
}

bool set_Signature(unsigned char* &Sign, size_t slen)
{
 if(slen<1) return false;
 Signature="";
 for(size_t i=0;i<slen;i++)
{
  Signature+=to_string((int)Sign[i]);
  if(i!=(slen-1)) Signature+="|";  
}

delete[] Sign;
return true;

}

unsigned char* get_Signature_in_unsigned(size_t &slen)
{
/*
Use only if the string Signature is set first
*/
  unsigned char** Sig=new unsigned char*;
  *Sig=NULL;
  stringstream convert;
  long int temp;
  vector<long int> temp_v;
  size_t pos=0;
  string msg=Signature;
  while((pos=msg.find("|"))!=std::string::npos)
  {
    convert << msg.substr(0,pos);
    convert >> temp;
    temp_v.push_back(temp);
    convert.str("");
    convert.clear();
    msg.erase(0, pos+1);
  }  
  convert << msg;
  convert >> temp;
  temp_v.push_back(temp);
  *Sig=new unsigned char[temp_v.size()];
   slen=temp_v.size();
   for(long int i=0;i<temp_v.size();i++)
   {
      (*Sig)[i]=(unsigned char)temp_v[i]; 
   }
   return *Sig;
}
  
bool Verify_Signature()
{
/*
Only if both string Signature and string payer_publickey is set first
*/ 
    ofstream out2("output.txt");
    out2 << payer_publickey;
    out2.close();
    FILE* fp;
    fp=fopen("output.txt","r+");
    EVP_PKEY* Pubkey2=PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    if(remove("output.txt")!= 0){cout<<"Error deleting file"<<endl; return false;}
    
    size_t slen1=0;
    unsigned char* sig2=(*this).get_Signature_in_unsigned(slen1);
 
    string buf="trans-"+(*this).construct_io_fields(0)+"-"+(*this).construct_io_fields(1)+"-"+to_string(trans_fee);
    char buffer[65];
    char* buf2=new char[buf.length()];
    strcpy(buf2, buf.c_str());
    sha256(buf2, buffer);

    bool a=Verify_ECDSA_Signature(sig2, slen1, buffer, Pubkey2);

    delete[] sig2;
    delete[] buf2;
    EVP_PKEY_free(Pubkey2);
    return a;
}




};



class Merkleblock
{
 public:
 string tophash,lhash,rhash; 
 long int index;

 Merkleblock()
 {
  lhash="";
  rhash="";
  string s=lhash+rhash;
  char buffer[65];
  char* s22=new char[s.length()];
  strcpy(s22,s.c_str());
  sha256(s22,buffer);
  string s1(buffer);
  tophash=s1;
  index=-1;
  delete s22[];
 }


Merkleblock(const Merkleblock& M)
{
  lhash=M.lhash;
  rhash=M.rhash;
  tophash=M.tophash;
  index=M.index;
}

Merkleblock& operator=(const Merkleblock& M)
{
  lhash=M.lhash;
  rhash=M.rhash;
  tophash=M.tophash;
  index=M.index;
  return *this;
}

void updateMerkleblock(string l_hash, string r_hash, long int index1)
 {
   lhash=l_hash;
   rhash=r_hash;
   char buffer[65];
   string s=lhash+rhash;
   char* s22=new char[s.length()];
   strcpy(s22,s.c_str());
   sha256(s22,buffer);
   string s1(buffer);
   tophash=s1;
   index=index1;  
   delete s22[];
 }
/* 
String format of the Merkleblock is mblock-index-tophash-lhash-rhash
*/ 


string merkleblockstring()
{
return "mblock-"+to_string(index)+"-"+tophash+"-"+lhash+"-"+rhash;
}

bool extractmerkleblock(string msg)
{

  vector<string> components;
  size_t pos=0;
  while((pos=msg.find("-"))!=std::string::npos)
  {
    components.push_back(msg.substr(0,pos));
    msg.erase(0, pos+1);
  }
     
     components.push_back(msg);
     if(components.size()!=5) return false;
     if(components[0]!="mblock") return false;
     
     stringstream convert(components[1]);
     convert >> index;
     convert.str("");
     convert.clear();
   
     tophash=components[2];
     lhash=components[3];
     rhash=components[4];
     char buffer[65];
   string s=lhash+rhash;
   char* s22=new char[s.length()];
   strcpy(s22,s.c_str());
   sha256(s22,buffer);
   string s1(buffer);
   if(tophash!=s1) return false;
   delete s22[];
   return true;
}



  
};

//"EmptyTransactionfiller"
class MerkleTree
{
// Depth is calculated including the root Merkleblock i.e if depth is 8, tree has 128 transactions
//The tree should be accessed from index=1; tree[0] is just a dummy Merkleblock

 public:
 string empty_trans;
 long int depth_tree;
 long int size_tree;
 Merkleblock* tree;
 Transaction* trans_lst;
 unordered_map<string, long int> hashpointer; 
~MerkleTree()
{
  delete[] tree;
  delete[] trans_lst;
  hashpointer.clear();
}


 MerkleTree() : hashpointer()
 { 
   empty_trans="EmptyTransactionfiller";
   depth_tree=8;
   size_tree=256;
   tree=new Merkleblock[256];
   trans_lst=new Transaction[128];
 }


MerkleTree(const MerkleTree& Mt)
{
  empty_trans=Mt.empty_trans;
  depth_tree=Mt.depth_tree;
  size_tree=Mt.size_tree;
  tree=new Merkleblock[size_tree];
  trans_lst=new Transaction[size_tree/2];
  for(long int i=0;i<size_tree;i++){tree[i]=Mt.tree[i];}
  for(long int i=0;i<(size_tree/2);i++){trans_lst[i]=Mt.trans_lst[i];} 
}

MerkleTree& operator=(const MerkleTree &Mt)
{
  empty_trans=Mt.empty_trans;
  depth_tree=Mt.depth_tree;
  size_tree=Mt.size_tree;
  tree=new Merkleblock[size_tree];
  trans_lst=new Transaction[size_tree/2];
  for(long int i=0;i<size_tree;i++){tree[i]=Mt.tree[i];}
  for(long int i=0;i<(size_tree/2);i++){trans_lst[i]=Mt.trans_lst[i];} 

  return *this;
}

bool Set_new_params(string newfiller, long int newdepth)
{
 if(newdepth<1) return false;
 empty_trans=newfiller; 
 depth_tree=newdepth;
 double base=2.00;
 size_tree=pow(base,depth_tree);
 delete[] tree;
 delete[] trans_lst;
 tree=NULL;
 trans_lst=NULL;
 tree=new Merkleblock[size_tree]; 
 trans_lst=new Transaction[size_tree/2];
 return true; 
}

bool buildtree_helper(long int _elems)
{
   if((2*_elems)>size_tree) return false;
   if((size_tree%_elems)!=0) return false;

   if(_elems==1) return true;
   
   long int _newelems=_elems/2;
   for(long int i=_newelems,j=_elems;i<_elems;i++,j+=2)
   {
      tree[i].updateMerkleblock(tree[j].tophash,tree[j+1].tophash,i);
   }
   return buildtree_helper(_newelems);
}



bool buildtree(vector<string>& trans_strings)
{
  long int size_base=size_tree/2;
  long int size_vec=trans_strings.size();
  if(size_vec>size_base) return false;  
  
  string temp;
  for(long int i=1;i<=size_base;i++)
  {
    if(i>size_vec) temp=empty_trans;
    else 
    {  
     temp=trans_strings[i-1];
     if(!trans_lst[i-1].Extract_trans(temp)) return false;
     
    }
    tree[size_base+i-1].updateMerkleblock(temp,"",size_base+i-1);
    if(i<=size_vec) 
    {
      hashpointer.insert(pair<string,long int>(tree[size_base+i-1].tophash, (i-1))); 
    }  
  }
  return buildtree_helper(size_base);
}


bool percolate_change(long int _start_index)
{
   if((_start_index>=size_tree)||_start_index<=0) return false;

   if(_start_index==1) return true;

   long int _nxt_index=_start_index/2;
   if(_start_index%2==0) tree[_nxt_index].updateMerkleblock(tree[_start_index].tophash, tree[_nxt_index].rhash, _nxt_index);
   else tree[_nxt_index].updateMerkleblock(tree[_nxt_index].lhash, tree[_start_index].tophash, _nxt_index);

   return percolate_change(_nxt_index);
}

bool updatetree(long int trans_index, string new_trans_str)
{
  long int size_base=size_tree/2;
  if(trans_index>size_base||trans_index<1) return false;

  if(!(hashpointer.find(tree[size_base+trans_index-1].tophash)==hashpointer.end())) hashpointer.erase(tree[size_base+trans_index-1].tophash);
  
  tree[size_base+trans_index-1].updateMerkleblock(new_trans_str,"",size_base+trans_index-1);
  trans_lst[trans_index-1].clearfields();

  if(!trans_lst[trans_index-1].Extract_trans(new_trans_str)) return false;
  hashpointer.insert(pair<string,long int>(tree[size_base+trans_index-1].tophash, (trans_index-1)));
  return percolate_change(size_base+trans_index-1);
}

/*
String format of representation-
mtree-depth_tree-size_tree-empty_trans-merkleblock1#merkleblock2#....#merkleblockn
*/



string merkletreestring()
{
string s1="mtree-"+to_string(depth_tree)+"-"+to_string(size_tree)+"-"+empty_trans+"-";
for(long int i=0;i<size_tree;i++)
{
s1+=tree[i].merkleblockstring();
if(i!=(size_tree-1)) s1+="#";
}
return s1;
}

bool extractmerkletree(string msg)
{
  hashpointer.clear();
  vector<string> components;
  size_t pos=0;
  while(((pos=msg.find("-"))!=std::string::npos)&&(components.size()<4))
  {
    components.push_back(msg.substr(0,pos));
    msg.erase(0, pos+1);
  }
     
     components.push_back(msg);
     if(components.size()!=5) return false;
     if(components[0]!="mtree") return false;
     
     stringstream convert(components[1]);
     convert >> depth_tree;
     convert.str("");
     convert.clear();
  
     convert << components[2];
     convert >> size_tree;
     convert.str("");
     convert.clear();
   
     empty_trans=components[3];
     double base=2.00;
     if(size_tree!=(pow(base,depth_tree))) return false;
     if(size_tree!=256)
     {
       delete[] tree;
       delete[] trans_lst;
       tree=NULL;
       trans_lst=NULL;
       tree=new Merkleblock[size_tree];
       trans_lst=new Transaction[size_tree/2];
     }
     string msg_new=components[4];
     
     pos=0;
     long int i=0;
     while((pos=msg_new.find("#"))!=std::string::npos)
     {
       if(!(tree[i].extractmerkleblock(msg_new.substr(0,pos)))) return false;
       msg.erase(0, pos+1);
       i++;
     }
    
     if(!(tree[i].extractmerkleblock(msg_new.substr(0,pos)))) return false;
   
     long int size_base=size_tree/2;
     
     for(long int y=0;y<size_base;y++)
     {
      if(!(trans_lst[y].Extract_trans(tree[size_base+y].lhash))) return false;
      hashpointer.insert(pair<string, long int>(tree[size_base+y].tophash,y));
     }

     return true;

}

bool hashverifytree_helper(long int level)
{
   if(level==0) return true;
   
   if(level>depth_tree) return false;
   double base=2.00;
   long int size_lvl=pow(base, level-1);
   for(long int i=size_lvl;i<=((2*size_lvl)-1);i++)
   {
     string temp=tree[i].lhash+tree[i].rhash;
     char* hert=new char[temp.length()];
     char buf[65];
     strcpy(hert,temp.c_str());
     sha256(hert,buf);
     string s11(buf);
     delete hert[];
     if(tree[i].tophash!=s11) return false;

     if(level==1) continue;

     long int k=i/2;
     if(i%2==0)
     { 
      if(tree[k].lhash!=tree[i].tophash) return false;
     }
     else
     { 
       if(tree[k].rhash!=tree[i].tophash) return false;
     }
   }
   return hashverifytree_helper(level-1);
}


bool hashverifytree()
{
 double base=2.00;
 if(!(pow(base,depth_tree)==size_tree)) return false;
 for(long int i=0;i<(size_tree/2);i++)
 {
   if((hashpointer.find(tree[i+(size_tree/2)].tophash))->second!=i) return false;
 }
 return hashverifytree_helper(depth_tree);
}

};

class block
{
public:
	string prev_hash;
	string top_hash;
	MerkleTree trans_tree;
	unsigned long long int nonce;
	long long int blockid;
	long int difficulty;
	time_t time_stamp;
	unsigned long long int nonce_max;

//size_chain is not sent or recieved as part of the block. It is just a helping varible for implementing the blockchain.
//size_chain indicates the size of the blockchain given block is a part of uptill and including this block.
        long long int size_chain;

block() : trans_tree()
{
	prev_hash="";
	nonce=0;
	difficulty=5;
	vector<string> temp;
	trans_tree.buildtree(temp);
	nonce_max=4294967296;
	time_stamp=std::time(0);
	blockid=1;

	string s11=to_string(blockid)+to_string(time_stamp)+prev_hash+trans_tree.tree[1].tophash+to_string(nonce);
	char* s111=new char[s11.length()];
	char buf[65];
	strcpy(s111,s11.c_str());
	sha256(s111,buf);
	string s222(buf);
	top_hash=s222;
        size_chain=1;
        delete s111[];
}

block(const block& bl)
{
	prev_hash=bl.prev_hash;
	nonce=bl.nonce;
	difficulty=bl.difficulty;
	trans_tree=bl.trans_tree;
	nonce_max=bl.nonce_max;
	time_stamp=bl.time_stamp;
	blockid=bl.blockid;
	top_hash=bl.top_hash;
        size_chain=bl.size_chain;
}

block& operator=(const block& bl)
{
	prev_hash=bl.prev_hash;
	nonce=bl.nonce;
	difficulty=bl.difficulty;
	trans_tree=bl.trans_tree;
	nonce_max=bl.nonce_max;
	time_stamp=bl.time_stamp;
	blockid=bl.blockid;
	top_hash=bl.top_hash;
        size_chain=bl.size_chain;
        return *this;
}

bool hashverifyblock()
{
	if(!trans_tree.hashverifytree()) return false;
	if(nonce>nonce_max) return false;
	if(difficulty>256) return false;
	string s11=to_string(blockid)+to_string(time_stamp)+prev_hash+trans_tree.tree[1].tophash+to_string(nonce);
	char* s111=new char[s11.length()];
	char buf[65];
	strcpy(s111,s11.c_str());
	sha256(s111,buf);
	string s222(buf);
        delete s111[];
	if(top_hash!=s222) return false;
	for(long int i=0;i<difficulty;i++)
	{
	if(top_hash[i]!='0') return false;
	}
	return true;

}

/*
string format of a block-
chain%blockid%time_stamp%prev_hash%Merkletreeinstringformat%nonce%difficulty%tophash
*/


string getblockstring()
{
 return to_string(blockid)+"%"+to_string(time_stamp)+"%"+prev_hash+"%"+(trans_tree.merkletreestring())+"%"+to_string(nonce)+"%"+to_string(difficulty)+"%"+top_hash;
}


bool extractblock(string msg)
{
     vector<string> components;
     size_t pos=0;
     while((pos=msg.find("%"))!=std::string::npos)
     {
      components.push_back(msg.substr(0,pos));
      msg.erase(0, pos+1);
     }
     
     components.push_back(msg);
     if(components.size()!=8) return false;
     if(components[0]!="chain") return false;
     
     stringstream convert(components[1]);
     convert >> blockid;
     convert.str("");
     convert.clear();
  
     convert << components[2];
     convert >> time_stamp;
     convert.str("");
     convert.clear();
     
     prev_hash=components[3];

     if(!trans_tree.extractmerkletree(components[4])) return false;

     convert << components[5];
     convert >> nonce;
     convert.str("");
     convert.clear();

     convert << components[6];
     convert >> difficulty;
     convert.str("");
     convert.clear();

     top_hash=components[7];
     size_chain=1;
     return true;
}


};






class nodeblockchain
{
	public:

	long long int check_fork_limit;
	long long int discard_fork_after;
	long long int confirmation_head;

	string nodepubkey;
        //Public key on node

	vector<block> Genisys_blockchain; 
        //Initialization
	vector<vector<block> > all_chains;
        //Data structure to keep track of all growing chains
	vector<pair<long long int, long long int> > previous_points; 
        //Helper data structure for above. Indicates prev block position of first block of each vector in all_chains
	unordered_map<string, pair<long long int, long long int> > Possible_fork_points;
        //Search prev block hash to find out which pre block does the discovered block references
               
 
	vector<map<pair<string, long int>, Transaction> > UTXO;
        //Unspent Transaction Outputs for head of each fork
	vector<map<pair<string, long int>, Transaction> > latest_STXO;
        //Spent Transactions for last few blocks of each fork
	vector<map<pair<string, long int>, Transaction> > nodeUTXO;
        //Unspent Transaction Outputs the given node can use for head of each fork
	vector<map<pair<string, long int>, Transaction> > latest_nodeSTXO;
        //Spent Transactions of the given node for last few blocks of each fork

        block curr_block;
        map<pair<string, long int>, Transaction> curr_UTXO;
        map<pair<string, long int>, Transaction> curr_latestSTXO;
        deque<Transaction> new_blck_trans; //Transactions to be included in the new block
        //Mining starts once number of Transactions exceeds 127
        deque<string> unproc_trans; //unprocessed Transaction strings
        deque<string> unproc_block; //unprocessed Block strings

	map<pair<string, long int>, Transaction> temp_nodeSTXO; 
        //For payments which are broadcasted by the node but not yet confirmed

	unordered_set<string> Sig_verified_trans_cache;
        //To prevent signature verification repeatedly

	pair<long long int, long long int> active_chain_head;
	pair<long long int, long long int> active_chain_last_confirmed_block;

	vector<Transaction> broadcast_buffer;
        //buffer of Transactions which need to broadcasted. Broadcast every 1 min.
	map<string, Transaction> successful_payments_by_node;
	map<string, Transaction> accepted_payments_to_node;

	nodeblockchain() : nodepubkey(), Genisys_blockchain(), all_chains(), Possible_fork_points(), UTXO(), latest_STXO(), nodeUTXO(), latest_nodeSTXO(), curr_block(), curr_UTXO(), curr_latestSTXO(), temp_nodeSTXO(), Sig_verified_trans_cache(), broadcast_buffer(), successful_payments_by_node(), accepted_payments_to_node(), new_blck_trans(), unproc_trans(), unproc_block() 
	{
	  check_fork_limit=20;
	  discard_fork_after=50;
	  confirmation_head=20;
	  active_chain_head=make_pair(-1,-1);
          previous_points.push_back(make_pair(-1,-1));
	  
	}

	nodeblockchain(vector<block> Gnsys_bch, string npubkey) : all_chains(), UTXO(), latest_STXO(), nodeUTXO(), latest_nodeSTXO(), curr_block(), curr_UTXO(), curr_latestSTXO(), temp_nodeSTXO(), Sig_verified_trans_cache(), broadcast_buffer(), successful_payments_by_node(), accepted_payments_to_node(), new_blck_trans(), unproc_trans(), unproc_block()
	{
	  nodepubkey=npubkey;
	  check_fork_limit=20;
	  discard_fork_after=50;
	  confirmation_head=20;
	  active_chain_head=make_pair(-1,-1);
	  active_chain_last_confirmed_block=make_pair(-1,-1);
	  Genisys_blockchain=Gnsys_bch;
	  previous_points.push_back(make_pair(-1,-1));
	  Possible_fork_points.insert(make_pair(Genisys_blockchain[Genisys_blockchain.size()-1].top_hash, make_pair(-1,-1)));
	}

        
        void process_trans()
        {
         	 Transaction T_tmp;
         
		 while(unproc_trans.size()!=0)
		 {
		          bool a=true;
		          T_tmp.Extract_trans(unproc_trans.front());
                          if(!T_tmp.Verify_Signature()) continue;
		          unproc_trans.pop_front();
		          long int total1=0;
		          map<pair<string, long int>, Transaction>::iterator itr1, itr2;
		          map<pair<string, long int>, Transaction> temp_STXO;

		          for(long long int j1=0;j1<(T_tmp.input_fields).size();j1++)
		          {
                            string temp1=(T_tmp.input_fields[j1]).first;
                            string field1=(T_tmp.input_fields[j1]).second;
                            itr1=curr_UTXO.find(make_pair(temp1, field1));
                            itr2=temp_STXO.find(make_pair(temp1, field1));
                            if((itr1==curr_UTXO.end())||(itr2!=temp_STXO.end()))
                            {
                             a=false;
                             break;
                            }
                            else
                            {
                             total1+=(itr1->second).output_fields[field1];
                             temp_STXO.insert(make_pair((itr1->first), (itr1->second)));
                            }                            
		          }
                  
	                   if(!a) continue;
                           
                         for(long long int j2=0;j2<(T_tmp.output_fields).size();j2++)
                         {
                           total1=total1-(T_tmp.output_fields[j2]).second;
                         }
                         
                         total1-=T_tmp.trans_fee;

                         if(total1>0) continue;
     
                         new_blck_trans.push_back(T_tmp);

                         for(itr2=temp_STXO.begin();itr2!=temp_STXO.end();itr2++)
                         {
                          if(curr_UTXO.find(itr2->first)!=curr_UTXO.end()) curr_UTXO.erase(itr2->first);
                          curr_latestSTXO.insert(make_pair(itr2->first, itr2->second));
                         }
		 }
        
        }


        bool startmining()
        {
         if(new_blck_trans.size()<128) {cout<<"Not enough Transanctions to start mining"<<endl; return false;}
         
         //deque<Transaction> new2;
         vector<string> Trans1;
         int i=0;
         for(i=0;i<128;i++)
         {
          Trans1.push_back((new_blck_trans.front()).Convert_to_String());
          new_blck_trans.pop_front();
         }

         if(!(curr_block.trans_tree).buildtree(Trans1)) return false;

         
         if(active_chain_head.first==-1&&active_chain_head.second==-1)
         {
           if(Genisys_blockchain.size()>0){
            Curr_block.prev_hash=Genisys_blockchain[Genisys_blockchain.size()-1].tophash;
            Curr_block.blockid=Genisys_blockchain[Genisys_blockchain.size()-1].blockid+1;}
         }
         else if(active_chain_head.first>-1&&active_chain_head.second>-1)
         {
          Curr_block.prev_hash=all_chains[active_chain_head.first][active_chain_head.second].tophash;
          Curr_block.blockid=all_chains[active_chain_head.first][active_chain_head.second].blockid+1;
          Curr_block.difficulty=all_chains[active_chain_head.first][active_chain_head.second].difficulty;
	 }
         else
         {return false;}

         Curr_block.time_stamp=std::time(0);
         if(!(*this).findnonce(Curr_block)) return false;

         return Update_all(Curr_block);
            
         }

         bool findnonce(block& Bk) //ensure Bk is well constructed 
         {
          string part=to_string(bk.blockid)+to_string(bk.time_stamp)+bk.prev_hash+((bk.trans_tree).tree[1]).tophash;
          while(bk.nonce<bk.nonce_max)
          {
                   string s11=part+to_string(bk.nonce);
		   char* s111=new char[s11.length()];
	           char buf[65];
	           strcpy(s111,s11.c_str());
	           sha256(s111,buf);
	           string s222(buf);
                   delete s111[];
                   bk.top_hash=s222;
		   
                   bool ans=true;
		   for(long int i=0;i<bk.difficulty;i++)
		   {
		    if(bk.top_hash[i]!='0') {ans=false;break;}
		   }
		  
                   if(ans) return ans;
		   bk.nonce++;
           }
           return false;
         }


	pair<long long int, long long int> getblockpos(long int forkid, long int pos1, long long int move_back)
	{
	 if(move_back==0) return make_pair(forkid, pos1);

	 if(pos1>=move_back) return make_pair(forkid, pos1-move_back);

	 if(forkid==0) return make_pair(-1, -1);

	 return getblockpos(previous_points[forkid].first, previous_points[forkid].second, move_back-pos1-1);
	}



	bool Update_Sig_cache(Transaction &Trans)
	{
	  if(Sig_verified_trans_cache.find(Trans.Transid)==Sig_verified_trans_cache.end())
	  {
	   if(!(Trans.Verify_Signature())) return false;   
	   Sig_verified_trans_cache.insert(Trans.Transid); 
	  }
	  return true;
	}

	bool reverse_change_TXO(block& blck, map<pair<string, long int>, Transaction>& UTXO_new, map<pair<string, long int>, Transaction>& latest_STXO_new, map<pair<string, long int>, Transaction>& nodeUTXO_new, map<pair<string, long int>, Transaction>& latest_nodeSTXO_new)
	{
	/*
	To Reverse change UTXO and latest_STXO, for each block, first remove all input fields of each Transaction in the block from latest_STXO and insert them into UTXO. Then remove all output fields of each Transaction in the block from UTXO (as they are now invalid). Note that this will also remove all the Transaction outputs which are created and referenced within the same block from latest_STXO without including them into UTXO.
	*/   
	  long int size_base=((blck.trans_tree).size_tree)/2;
	  map<pair<string, long int>, Transaction>::iterator itr2,itr3, itr4, itr5;
	  
	  for(long int i=0;i<size_base;i++)
	  {
	   for(long int j=0;j<(((blck.trans_tree).trans_lst[size_base+i]).input_fields).size();j++)
	   {
	    itr3=latest_STXO_new.find(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j));
	    if(itr3==latest_STXO_new.end()) {cout<<"Invariant is not same!! "<<"Have to Modify the code!!! "<<endl; return false;}
	    UTXO_new.insert(make_pair(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j), itr3->second));

	    itr4=latest_nodeSTXO_new.find(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j));
	    if(itr4!=latest_STXO_new.end()) 
	    {
	     nodeUTXO_new.insert(make_pair(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j), itr4->second));
	     latest_nodeSTXO_new.erase(itr4);
	    } 
	    latest_STXO_new.erase(itr3);
	   }
	  }

	  for(long int i=0;i<size_base;i++)
	  {
	   for(long int j=0;j<(((blck.trans_tree).trans_lst[size_base+i]).output_fields).size();j++)
	   {
	      itr2=UTXO_new.find(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j));
	      itr5=nodeUTXO_new.find(make_pair(((blck.trans_tree).trans_lst[size_base+i]).Transid, j));
	      if(itr2!=UTXO_new.end()) UTXO_new.erase(itr2);
	      if(itr5!=nodeUTXO_new.end()) nodeUTXO_new.erase(itr5);
	   }
	  }

	   return true;
	}



	bool Update_all(block& new_block)
	{
	   long int forkid;
	   unordered_map<string, pair<long long int, long long int> >::iterator itr1=Possible_fork_points.find(new_block.prev_hash);
	   if(itr1==Possible_fork_points.end()) return false;
	 
	   if(((itr1->second).first==-1)&&((itr1->second).second==-1))
	   { 
	     
	   }
	   else if(all_chains[(itr1->second).first].size()==(((itr1->second).second)+1))
	    {
	     new_block.size_chain=all_chains[(itr1->second).first][(itr1->second).second].size_chain+1;
	     forkid=(itr1->second).first;
	    }
	   else
	   {
	    new_block.size_chain=all_chains[(itr1->second).first][(itr1->second).second].size_chain+1;
	    map<pair<string, long int>, Transaction> UTXO_new, STXO_new, nodeUTXO_new, nodeSTXO_new;
	    UTXO_new.insert(UTXO[(itr1->second).first].begin(), UTXO[(itr1->second).first].end());
	    STXO_new.insert(latest_STXO[(itr1->second).first].begin(), latest_STXO[(itr1->second).first].end());

	    nodeUTXO_new.insert(nodeUTXO[(itr1->second).first].begin(), nodeUTXO[(itr1->second).first].end());
	    nodeSTXO_new.insert(latest_nodeSTXO[(itr1->second).first].begin(), latest_nodeSTXO[(itr1->second).first].end());
	    
	    long int i1=all_chains[(itr1->second).first].size()-1;
	    long int i2=((itr1->second).second);
	    while(i1!=i2)
	    {
	     if(!reverse_change_TXO(all_chains[(itr1->second).first][i1], UTXO_new, STXO_new, nodeUTXO_new, nodeSTXO_new))
	     {cout<<"Major err!"<<endl; return false;}
	     --i1;
	    }
	 
	    UTXO.push_back(UTXO_new);
	    latest_STXO.push_back(STXO_new);
	    nodeUTXO.push_back(nodeUTXO_new);
	    latest_nodeSTXO.push_back(nodeSTXO_new);

	    previous_points.push_back(make_pair((itr1->second).first, (itr1->second).second));
	    forkid=previous_points.size()-1;
	   }

	   if(!new_block.hashverifyblock()) return false;

	   long int size_base=((new_block.trans_tree).size_tree)/2;
	   map<pair<string, long int>, Transaction> local_UTXO;
	   map<pair<string, long int>, Transaction> local_STXO;

	   for(long int i=0;i<size_base;i++)
	   {
	     long int total=0;
	     
	     if(!Update_Sig_cache((new_block.trans_tree).trans_lst[size_base+i])) return false;
	    
	     for(long long int j=0;j<(((new_block.trans_tree).trans_lst[size_base+i]).input_fields.size());j++)
	     {
	     
	      string temp=(((new_block.trans_tree).trans_lst[size_base+i]).input_fields[j]).first;
	      long long int field=(((new_block.trans_tree).trans_lst[size_base+i]).input_fields[j]).second;

	      map<pair<string, long int>, Transaction>::iterator it=UTXO[forkid].find(make_pair(temp,field));
	      map<pair<string, long int>, Transaction>::iterator it22=nodeUTXO[forkid].find(make_pair(temp,field));

	      if(((it->second).output_fields[field]).first!=((new_block.trans_tree).trans_lst[size_base+i]).payer_publickey) return false;


	      if(it==UTXO[forkid].end())
	       {
		it=local_UTXO.find(make_pair(temp,field)); 
		if((it==local_UTXO.end())||(local_STXO.find(make_pair(temp,field))!=local_STXO.end())) return false;
		total+=((it->second).output_fields[field]).second; 
		local_UTXO.erase(make_pair(temp,field));
		local_STXO.insert(make_pair(make_pair(temp,field), ((new_block.trans_tree).trans_lst[size_base+i])));           
	       }
	      else
	      {
	       if(local_STXO.find(make_pair(temp,field))!=local_STXO.end()) return false;
	       total+=((it->second).output_fields[field]).second;
	       local_STXO.insert(make_pair(make_pair(temp,field), ((new_block.trans_tree).trans_lst[size_base+i])));
	      }        

	     }

	     for(long long int j=0;j<(((new_block.trans_tree).trans_lst[size_base+i]).output_fields.size());j++)
	     {
	      string temp=(((new_block.trans_tree).trans_lst[size_base+i]).output_fields[j]).first;
	      long int amount=(((new_block.trans_tree).trans_lst[size_base+i]).output_fields[j]).second;
	      total=total-amount;
	      if(total<0) return false;
	      local_UTXO.insert(make_pair(make_pair(temp,j), ((new_block.trans_tree).trans_lst[size_base+i])));
	     }

	    total=total-(((new_block.trans_tree).trans_lst[size_base+i]).trans_fee);
	    if(total!=0) return false;
	  }
	//Now Update UTXOs and STXOs as the block is valid

	  UTXO[forkid].insert(local_UTXO.begin(), local_UTXO.end());
	  latest_STXO[forkid].insert(local_STXO.begin(), local_STXO.end());
	  map<pair<string, long int>, Transaction>::iterator itr;

	  for(itr=local_UTXO.begin(); itr!=local_UTXO.end(); ++itr)
	  {
	   if((itr->second).payer_publickey==nodepubkey){nodeUTXO[forkid].insert(make_pair(itr->first, itr->second));}
	  }

	  for(itr=local_STXO.begin(); itr!=local_STXO.end(); ++itr)
	  {
	    if(UTXO[forkid].find(itr->first)!=UTXO[forkid].end()) UTXO[forkid].erase(itr->first);
	    if(nodeUTXO[forkid].find(itr->first)!=nodeUTXO[forkid].end()) 
	     {
	      latest_nodeSTXO[forkid].insert(make_pair(itr->first, itr->second));
	      nodeUTXO[forkid].erase(itr->first);
	     }
	  } 
	// Add the block to all_chains and update Possible_fork_points and Sig_verified_trans_cache

	if(all_chains.size()==forkid)
	{
	  vector<block> temp_a;
	  temp_a.push_back(new_block);
	  all_chains.push_back(temp_a);
	  Possible_fork_points.insert(make_pair(new_block.top_hash, make_pair(forkid, 0)));
	  pair<long long int, long long int> aw11=getblockpos(forkid, 0, check_fork_limit);
	  
	  if((aw11.first!=-1)&&(aw11.second!=-1)) 
	  {
	  
	   if(Possible_fork_points.find(all_chains[aw11.first][aw11.second].top_hash)!=Possible_fork_points.end())
	    {
	     Possible_fork_points.erase(all_chains[aw11.first][aw11.second].top_hash);
	    }

	   long int size_base1212=(all_chains[aw11.first][aw11.second].trans_tree).size_tree/2;
	   for(long int i4=0;i4<size_base1212;i4++)
	   {
	    if(Sig_verified_trans_cache.find(((all_chains[aw11.first][aw11.second].trans_tree).trans_lst[size_base1212+i4]).Transid)!=Sig_verified_trans_cache.end())
	    {
	      Sig_verified_trans_cache.erase(((all_chains[aw11.first][aw11.second].trans_tree).trans_lst[size_base1212+i4]).Transid);
	    }     
	   }

	  }

	}
	else if(all_chains.size()<forkid)
	{
	  cout<<"Major err!!! in blocktree..check code"<<endl;
	  return false;  
	}

	else
	{
	 all_chains[forkid].push_back(new_block);
	 Possible_fork_points.insert(make_pair(new_block.top_hash, make_pair(forkid, all_chains[forkid].size()-1)));
	 
	 pair<long long int, long long int> aw11=getblockpos(forkid, all_chains[forkid].size()-1, check_fork_limit);
	 
	 if((aw11.first!=-1)&&(aw11.second!=-1)) 
	 {
	  if(Possible_fork_points.find(all_chains[aw11.first][aw11.second].top_hash)!=Possible_fork_points.end())
	   {
	    Possible_fork_points.erase(all_chains[aw11.first][aw11.second].top_hash);
	   }

	   long int size_base1212=(all_chains[aw11.first][aw11.second].trans_tree).size_tree/2;

	   for(long int i4=0;i4<size_base1212;i4++)
	   {
	    if(Sig_verified_trans_cache.find(((all_chains[aw11.first][aw11.second].trans_tree).trans_lst[size_base1212+i4]).Transid)!=Sig_verified_trans_cache.end())
	    {
	      Sig_verified_trans_cache.erase(((all_chains[aw11.first][aw11.second].trans_tree).trans_lst[size_base1212+i4]).Transid);
	    }     
	   }

	 }

	}
	//Update active_chain_head, active_chain_last_confirmed_block, accepted_payments_to_node and discard some forks from Possible_fork_points

	if(all_chains[active_chain_head.first][active_chain_head.second].size_chain<all_chains[forkid][all_chains[forkid].size()-1].size_chain)
	  {
	     active_chain_head.first=forkid;
	     active_chain_head.second=all_chains[forkid].size()-1;
	     pair<long long int, long long int> last_confirmed_block=active_chain_last_confirmed_block;
	     active_chain_last_confirmed_block=getblockpos(forkid, all_chains[forkid].size()-1, confirmation_head);
	     
	     //update accepted_payments_to_node, successful_payments_by_node, broadcast_buffer and temp_nodeSTXO
	     
	     if((active_chain_last_confirmed_block.first!=-1)&&(active_chain_last_confirmed_block.second!=-1))
	     {
		if((active_chain_last_confirmed_block.first==last_confirmed_block.first)&&(active_chain_last_confirmed_block.second==(last_confirmed_block.second+1)))
		{
		       long long int e1=active_chain_last_confirmed_block.first, e2=active_chain_last_confirmed_block.second;
		       long int size_base2222=(all_chains[e1][e2].trans_tree).size_tree/2;
		      
		       for(long int er2=0;er2<size_base2222;er2++)
		       {
		         
		         if(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).payer_publickey==nodepubkey)
		         {
		           successful_payments_by_node.insert(make_pair(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).Transid, ((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2])));

		           broadcast_buffer.erase(std::remove_if(broadcast_buffer.begin(),broadcast_buffer.end(), [&, e1, e2](Transaction& T) 
{ return ( ((((*this).all_chains[e1][e2]).trans_tree).trans_lst[size_base2222+er2])==T );} ), broadcast_buffer.end());

		         //Also update temp_nodeSTXO
		         for(long int hk=0;hk<(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).input_fields).size();hk++)
		          {
		            string hk_tmp=(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).input_fields[hk]).first;
		            long int hk_fld=(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).input_fields[hk]).second;

		            if(temp_nodeSTXO.find(make_pair(hk_tmp, hk_fld))!=temp_nodeSTXO.end()) temp_nodeSTXO.erase(make_pair(hk_tmp, hk_fld));
		          }

		          
		         }
		         

			 for(long int er3=0;er3<(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).output_fields).size();er3++)
		         {
		          if((((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).output_fields[er3]).first==nodepubkey)
		           {
		            accepted_payments_to_node.insert(make_pair(((all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]).Transid, (all_chains[e1][e2].trans_tree).trans_lst[size_base2222+er2]));
		            break;
		           }
		         }


		       }
		 
		}
	     }
    
     //discard some forks from Possible_fork_points
     long long int longest_size_chain=all_chains[forkid][all_chains[forkid].size()-1].size_chain;
     for(long long int yu=0;yu<all_chains.size();yu++)
     {
       long long int len=all_chains[yu].size();
       if((longest_size_chain-all_chains[yu][len-1].size_chain)>=discard_fork_after)
       {
         for(long long int ki=0;ki<len;ki++)
         {
          if(Possible_fork_points.find(all_chains[yu][ki].top_hash)!=Possible_fork_points.end())
          { 
            Possible_fork_points.erase(all_chains[yu][ki].top_hash);
          }
         }
       }
     }     
 

 }


	//Now remove the block from the STXOs which is check_fork_limit blocks before the new_block if such a block exists 

	pair<long long int, long long int> awq=getblockpos(forkid, all_chains[forkid].size()-1, check_fork_limit);
	if((awq.first!=-1)&&(awq.second!=-1))
	{
	 long int size_base11=((all_chains[awq.first][awq.second].trans_tree).size_tree)/2;

	 for(long int i=0;i<size_base11;i++)
	 {
	  for(long long int j=0;j<(((all_chains[awq.first][awq.second].trans_tree).trans_lst[size_base11+i]).input_fields.size());j++)
	  {

	   string temp=(((all_chains[awq.first][awq.second].trans_tree).trans_lst[size_base11+i]).input_fields[j]).first;
	   long long int field=(((all_chains[awq.first][awq.second].trans_tree).trans_lst[size_base11+i]).input_fields[j]).second;

	   if(latest_STXO[forkid].find(make_pair(temp, field))!=latest_STXO[forkid].end())
	    {
	     latest_STXO[forkid].erase(make_pair(temp, field));
	    }

	   if(latest_nodeSTXO[forkid].find(make_pair(temp, field))!=latest_nodeSTXO[forkid].end())
	    {
	     latest_nodeSTXO[forkid].erase(make_pair(temp, field));
	    }   

	  }
	 }
	}



 return true;
}


};







class node
{
   string pubkey_filename;
   EVP_PKEY* key;
   EVP_PKEY_CTX* pctx;
   EVP_PKEY_CTX* kctx;
   EVP_PKEY* params;

   vector<Transaction> payments_to_make;
   vector<Transaction> payments_to_confirm;

   public:
   EVP_PKEY* Pubkey;
   nodeblockchain Chain;

   node()
   {
     pubkey_filename="Pubkey.txt";
     key=NULL;
     pctx=NULL;
     kctx=NULL;
     params=NULL;
     if(Generate_params_key_ECDSA(params,key,pctx,kctx)) cout<<"Keys and Parameters successfully generated!"<<endl;
     else cout<<"Error in generating keys and parameters"<<endl; 
     FILE* fp;
     fp=fopen("Pubkey.txt","w+");
     PEM_write_PUBKEY(fp,key);  
     fclose(fp);

     string pubkey111="";
     ifstream nameFileout;
     nameFileout.open(pubkey_filename);
     string line;
     while(std::getline(nameFileout, line))
     {
       pubkey111+=line;
       pubkey111+='\n';
     }     
     Chain.nodepubkey=pubkey111;
     nameFileout.close();
   }

   bool complete_signature_publickey(Transaction& T)
   {
     /*
      Returns true if it assigns the string Signature of the Transaction T successfully 
     */
     string buf="trans-"+T.construct_io_fields(0)+"-"+T.construct_io_fields(1)+"-"+to_string(T.trans_fee);
     char buffer[65];
     char* buf2=new char[buf.length()];
     strcpy(buf2,buf.c_str());
     sha256(buf2, buffer);
     //buffer contains the hash to be signed.It would be hashed again by while signing -> double hashing.
     size_t* slen_sig=new size_t;
     unsigned char* Sign=Create_ECDSA_Signature(slen_sig, key, buffer);
     delete buf2[];
     return T.set_Signature(Sign, *slen_sig);
   }


  bool add_new_broadcast_transaction(vector<pair<string, long int> > &payees)
  {
   Transaction T_new;
   long int total=0;
    for(long int i=0;i<payees.size();i++)
    {
     (T_new.output_fields).push_back(payees[i]);
     total+=payees[i].second;
    }

   map<pair<string, long int>, Transaction>::iterator itr1;
   long int frkid=(Chain.active_chain_head).first;

   map<pair<string, long int>, Transaction> tmp_nodeSTXO;

    // find a new UTXO which is old enough      
	    for(itr1=(Chain.nodeUTXO[frkid]).begin();itr1!=(Chain.nodeUTXO[frkid]).end();itr1++)
	    { 
	      pair<long long int, long long int> local_iter=Chain.active_chain_head; 
	      bool tr=true;

	      while(local_iter.first!=((Chain.active_chain_last_confirmed_block).first)&&local_iter.second!=((Chain.active_chain_last_confirmed_block).second))
	      {
		       if((((Chain.all_chains[local_iter.first][local_iter.second]).trans_tree).hashpointer).find((itr1->first).first)!=(((Chain.all_chains[local_iter.first][local_iter.second]).trans_tree).hashpointer).end())
			{
			  tr=false;
			  break;
			}
		
		       if(local_iter.second==0)
		       {
			 local_iter=(Chain.previous_points[local_iter.first]);
		       }
		       else
		       {
			local_iter=make_pair(local_iter.first, (local_iter.second)-1);
		       }

	      }

	      if(((Chain.temp_nodeSTXO).find(itr1->first)!=(Chain.temp_nodeSTXO).end())||(tmp_nodeSTXO.find(itr1->first)!=tmp_nodeSTXO.end()))
	      {
	       tr=false;
	      }

	      tmp_nodeSTXO.insert(make_pair(itr1->first,itr1->second));
	       
	      if(tr)
	      {
	       total-=((itr1->second).output_fields[(itr1->first).second]).second;
	       (T_new.input_fields).push_back(itr1->first);
	      }

	      if(total<0) break;
	    }
	  
	    if(total>0) return false;

	    map<pair<string, long int>, Transaction >::iterator itr2;
	    for(itr2=tmp_nodeSTXO.begin();itr2!=tmp_nodeSTXO.end();itr2++)
	    {
	     (Chain.temp_nodeSTXO).insert(make_pair(itr2->first, itr2->second));
	    }

	    T_new.trans_fee=(-1*total); 
	    T_new.payer_publickey=Chain.nodepubkey;
	    if(!(*this).complete_signature_publickey(T_new)) return false;
   
	   //Assign Transid   
	   string buf=T_new.Convert_to_String();
	   char buffer[65];
	   char* buf2=new char[buf.length()];
	   strcpy(buf2,buf.c_str());
	   sha256(buf2, buffer); 
	   string sss(buffer);
	   T_new.Transid=sss; 
	   delete[] buf2; 

	   //Add to broadcast_buffer of Chain
	   (Chain.broadcast_buffer).push_back(T_new);
	   return true;

  }



};



void broadcast_message(breep::tcp::network& net, string msg)
{
  long int size=msg.length();
  char buffer[65];
  char* buf2=new char[size];
  strcpy(buf2, msg.c_str());
  sha256(buf2, buffer);
  string msg_hash(buffer);
  delete[] buf2;

  long int packetid=0; 
  
  while(msg.length()>3500)
  {
   string tmp=msg_hash+"$"+to_string(packetid)+"$"+msg.substr(0,3500);
   net.send_object(tmp);
   msg.erase(0,3500);
   packetid++;
  }

  string tmp1=msg_hash+"$$"+msg;
  net.send_object(tmp);
}

int main(int argc, char* argv[])
{
/*  
    FILE* fp;
    fp=fopen("Pubkey.txt","w+");
 
    EVP_PKEY_CTX* pctx=NULL;
    EVP_PKEY_CTX* kctx=NULL;
    EVP_PKEY* params=NULL;
    EVP_PKEY* key=NULL;
    cout<<Generate_params_key_ECDSA(params,key,pctx,kctx)<<endl;
    cout<<PEM_write_PUBKEY(fp,key)<<endl;
    

    FILE* newfp;
    newfp=freopen("Pubkey.txt","r+",fp);
    
    EVP_PKEY* Pubkey1=PEM_read_PUBKEY(newfp, NULL, NULL, NULL);
    fclose(newfp);

    string pubkey111="";
    ifstream nameFileout;
    nameFileout.open("Pubkey.txt");
    string line;
    while(std::getline(nameFileout, line))
    {
       pubkey111+=line;
       pubkey111+='\n';
    }
    cout<<"pubkey111:"<<endl;
    cout<<pubkey111<<endl;
    nameFileout.close();

    ofstream out1111("output.txt");
    out1111 << pubkey111;
    out1111.close();



    char buffer[65];
    sha256("string", buffer);
    printf("%s\n", buffer);
 
    size_t* slen=new size_t;
    unsigned char* Sign=Create_ECDSA_Signature(slen, key, buffer);
    cout<<"Above String is signed. Signature: "<<endl;
    printf("%s\n", Sign);

    string test(reinterpret_cast<char*>(Sign), *slen);
    unsigned char* mqw1111=new unsigned char[*slen];
    strcpy((char*)mqw1111, test.c_str());
    printf("%s\n", mqw1111);
    for(size_t i=0;i<*slen;i++)
    {
      mqw1111[i]=(unsigned char)((int)Sign[i]);
    }

    string test2(buffer, 65);
    char* buff1111;

    cout<<test.length()<<"   "<<*slen<<endl;
        

    if(!Verify_ECDSA_Signature(mqw1111, test.length(), buffer, Pubkey1)){cout<<"Invalid Signature"<<endl;}
    else{cout<<"Signature verified by Public key"<<endl;}

    
    return 0;

*/
if (argc != 2 && argc != 4) {
		std::cerr<< "Usage: " << argv[0] << " <hosting port> [<target ip> <target port>]\n";
		return 1;
	}

	std::string nick;
	std::cout << "Enter your Nick: ";
	std::getline(std::cin, nick);

	chat_manager chat(nick);

	breep::tcp::network network(std::atoi(argv[1]));

	network.add_data_listener<name>([&chat](breep::tcp::netdata_wrapper<name>& dw) -> void {
		chat.name_received(dw);
	});
	network.add_data_listener<std::string>([&chat](breep::tcp::netdata_wrapper<std::string>& dw) -> void {
		chat.message_received(dw);
	});

	network.add_connection_listener([&chat](breep::tcp::network& net, const breep::tcp::peer& peer) -> void {
		chat.connection_event(net, peer);
	});

	network.add_disconnection_listener([&chat](breep::tcp::network& net, const breep::tcp::peer& peer) -> void {
		chat.connection_event(net, peer);
	});

	if (argc == 2) {
		network.awake();
	} else {
		if(!network.connect(boost::asio::ip::address::from_string(argv[2]), std::atoi(argv[3]))) {
			std::cerr << "Connection failed.\n";
			return 1;
		}
	}

/*
	std::string message;
	std::getline(std::cin, message);
	while (message != "/q") {
		network.send_object(message);
		std::getline(std::cin, message);
	}
*/

        



	network.disconnect();
	return 0;
}
