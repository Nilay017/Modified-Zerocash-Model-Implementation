#include <iostream>
#include <ctime>
#include <bits/stdc++.h>
#include <openssl/sha.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sstream>

using namespace std;


/*
Format of the transaction message string:

"trans-transid1|outfield1#transid2|outfield2#transid3|outfield3-pubkey1|amount#pubkey2|amount2-transfee-signature-payerpublickey"

*/ 


class Transaction
{
  public:

  string transid;
  string payer_publickey;
  vector<pair<long long,long long> > input_fields;
  vector<pair<long long,long long> > output_fields;
  long long trans_fee;
  string Signature;
/////Variables not sent by msg////
//  EVP_PKEY* Pubkey11;
//  unsigned char* Sign;
//  size_t siglen;
 // 

Transaction()
{
    

}

Transaction(const Transaction &T)
{
  payer_publickey=T.payer_publickey;
  input_fields=T.input_fields;
  output_fields=T.output_fields;
  trans_fee=T.trans_fee;
  Signature=T.Signature;
}
  
Transaction(vector< pair<long long, long long> > a, vector< pair<long long, long long> > b, long long t, string sign, string pubkey)
  {
    input_fields=a;
    output_fields=b;
    trans_fee=t;
    Signature=sign;
    payer_publickey=pubkey;
}


Transaction& operator=(const Transaction &T)
{
  payer_publickey=T.payer_publickey;
  input_fields=T.input_fields;
  output_fields=T.output_fields;
  trans_fee=T.trans_fee;
  Signature=T.Signature;
  return *this;
}


   bool resolve_fields(string fieldstr,int field_type)
  {
   string msg,msg2;
   size_t pos, pos2;
   long long temp_1,temp_2;
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


        if(field_type==0) input_fields.push_back(pair<long long,long long>(temp_1,temp_2));
        else output_fields.push_back(pair<long long,long long>(temp_1,temp_2));

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
        
	if(field_type==0) input_fields.push_back(pair<long long,long long>(temp_1,temp_2));
        else output_fields.push_back(pair<long long,long long>(temp_1,temp_2));

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

     return true;
  }


string construct_io_fields(int field_type)
{
  vector<pair<long long,long long> >* ref;
  string temp,out="";

  if(field_type==0) ref=&input_fields;
  else ref=&output_fields;

  long long size=ref->size();   
  for (long long i = 0; i < ref->size(); i++)
  {
   temp=to_string((ref->at(i)).first)+"|"+to_string((ref->at(i)).second);
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
  const char* s11=s.c_str();
  char* s22;
  memcpy(s22,s11,s.length());
  sha256(s22,buffer);
  string s1(buffer);
  tophash=s1;
  index=-1;
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
   const char* s11=s.c_str();
   char* s22;
   memcpy(s22,s11,s.length());
   sha256(s22,buffer);
   string s1(buffer);
   tophash=s1;
   index=index1;  
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
   const char* s11=s.c_str();
   char* s22;
   memcpy(s22,s11,s.length());
   sha256(s22,buffer);
   string s1(buffer);
   if(tophash!=s1) return false;

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


 MerkleTree()
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



bool buildtree(vector<string> trans_strings)
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
     char* hert;
     char buf[65];
     memcpy(hert,temp.c_str(),temp.size());
     sha256(hert,buf);
     string s11(buf);
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

block()
{
	prev_hash="";
	nonce=0;
	difficulty=7;
	vector<string> temp;
	trans_tree.buildtree(temp);
	nonce_max=4294967296;
	time_stamp=std::time(0);
	blockid=1;

	string s11=to_string(blockid)+to_string(time_stamp)+prev_hash+trans_tree.tree[1].tophash+to_string(nonce);
	char* s111;
	char buf[65];
	memcpy(s111,s11.c_str(),s11.size());
	sha256(s111,buf);
	string s222(buf);
	top_hash=s222;
        size_chain=1;
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
	char* s111;
	char buf[65];
	memcpy(s111,s11.c_str(),s11.size());
	sha256(s111,buf);
	string s222(buf);
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


class blockchain
{
public:
long long int check_fork_limit;
long long int discard_fork_after;
long long int confirmation_head;

vector<block> Genisys_blockchain;
vector<vector<block> > all_chains;
vector<pair<long long int, long long int> > previous_points;

unordered_map<string, pair<long long int, long long int> > Possible_fork_points;
map<string, Transaction> UTXO;

pair<long long int, long long int> active_chain_head;
pair<long long int, long long int> active_chain_last_confirmed_block;

blockchain()
{
  check_fork_limit=20;
  discard_fork_after=50;
  confirmation_head=10;
  active_chain_head=make_pair(-1,-1);
  
}

blockchain(vector<block> Gnsys_bch)
{
  check_fork_limit=20;
  discard_fork_after=50;
  confirmation_head=10;
  active_chain_head=make_pair(-1,-1);
  Genisys_blockchain=Gnsys_bch;
  previous_points.push_back(make_pair(-1,-1));
  Possible_fork_points.insert(make_pair(Genisys_blockchain[Genisys_blockchain.size()-1].top_hash, make_pair(-1,-1)));
}


//bool updateUTXO(block& new_block)
//{
 //if(!new_block.hashverify()) return false;
 // 
 //long int size_base=((new_block.trans_tree).size_tree)/2;
 //for(long int i=0;i<size_base;i++)
// {
//   (new_block.trans_tree).trans_lst[size_base+i]
// }  


//}

bool updateblockchain(block new_block)
{



}

};







class node
{
   string pubkey_filename;
   EVP_PKEY* key;
   EVP_PKEY_CTX* pctx;
   EVP_PKEY_CTX* kctx;
   EVP_PKEY* params;

   vector<Transaction> unspend_Trans;
   vector<Transaction> payments_to_make;
   vector<Transaction> payments_to_confirm;
   vector<string> verified_trans_cache;
   public:
   EVP_PKEY* Pubkey;

   node()
   {
     pubkey_filename="Pubkey.txt";
     key=NULL;
     pctx=NULL;
     kctx=NULL;
     params=NULL;
     if(Generate_params_key_ECDSA(params,key,pctx,kctx)) cout<<"Keys and Parameters successfully generated!"<<endl;
     else cout<<"Error in generating keys and parameters"<<endl;        
   }

  

};





int main()
{
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
    if(!Verify_ECDSA_Signature(mqw1111, test.length(), buffer, Pubkey1)) cout<<"Invalid Signature"<<endl;
    else cout<<"Signature verified by Public key"<<endl;
    return 0;
}
