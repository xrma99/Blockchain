
# coding: utf-8

# In[1]:


import hashlib
import json
import time
import sys
import pathlib
import base58
from base58 import b58encode, b58decode
import binascii
import ecdsa
from ecdsa import SigningKey
from ecdsa import SECP256k1,keys


# In[2]:


def doubleSHA256(s):#对string s进行double SHA256加密
    x = hashlib.sha256()
    x.update(str(s).encode())   
    tmp=str(x.hexdigest())
   
    y=hashlib.sha256()
    y.update(tmp.encode())  
   
    return str(y.hexdigest()) #返回双重加密之后的结果


# In[3]:


class Merklenode:#merkle链
    def __init__(self,h):
        self.hashvalue=h
        self._next=None

    def addnode(self,n):#新node的hashvalue值
        node=self
        while node._next:
            node=node._next
        newnode=Merklenode(n)
        node._next=newnode

    def bi_merge(self,theotherhash):#二进制合并
        s=str(self.hashvalue)+str(theotherhash)
        self.hashvalue=doubleSHA256(s)
        


# In[4]:


class transaction:
    def __init__(self,sendsign,amount,receiversign):#发送者签名，金额，收款者签名
        self.sender=sendsign
        self.receiver=receiversign
        self.amount=amount
        
    def __repr__(self):
        return str(str(self.sender)+"\t"+str(self.amount)+"\t"+str(self.receiver)+"\n")
    
    def verify(self,utxo):#验证交易是否有足够余额
        balance=getbalance(utxo,self.sender)
        if(balance < self.amount):
            print(balance)
            return False
        else:
            return True#交易有效
        
    def toTrans(self,utxo):
        if(self.verify(utxo)==False):#验证是否有充足余额
            print("Not enougn balance")
            return None

        standard=self.amount
        r=utxo
        
        Thead=None
        flag=0
        
        while standard>0:#待转的钱还没有转完
            
            if flag==0:#第一次是从utxo开始往后求第一条utxo记录
                r=getfirstrelated(r,self.sender)
                flag=1
            else:#之后就是从r._next开始，一定要._next
                r=getfirstrelated(r._next,self.sender)
            if(standard<r.amount):
                Tinput=document(r.amount,r.people,r.flag)
                Toutsc=document(r.amount-standard,self.sender,0)
                Toutdst=document(standard,self.receiver,0)
            else:
                Tinput=document(r.amount,r.people,r.flag)
                Toutsc=document(0,self.sender,0)
                Toutdst=document(r.amount,self.receiver,0)
            
            Tnode=Transaction(Tinput,Toutsc,Toutdst)
            
            if not Thead:
                Thead=Tnode
            else:
                tmp=Thead
                while tmp._next:
                    tmp=tmp._next
                tmp._next=Tnode
                
            standard-=r.amount
            
        
        return Thead


# In[5]:


class document:
    def __init__(self,a,p,f):
        self.amount=a
        self.people=p
        self.flag=f #是否被使用 0未被使用，1已经被使用
        self._next=None #在UTXO池中被利用
    
    def tostr(self):
        return str(self.amount)+str(self.people)+str(self.flag)
    
    def packaging(self):
        return str(self.amount)+"\t"+str(self.people)+"\t"+str(self.flag)+"\n"
    
    def adddocument(self,newdocu):
        node=self
        while node._next:
            node=node._next
        node._next=newdocu
    
    def __repr__(self):
        return self.packaging()


# In[6]:


#正式版的交易记录,存在区块链里的
class Transaction:
    def __init__(self,inp,outsc,outdst):
        #有25块钱的Alice给Bob 17块钱
        self.input=inp #25 Alice
        self.outputsc=outsc #8 Alice
        self.outputdst=outdst #17 Bob
        self._next=None
    
    def __repr__(self):
        return self.input.packaging()+self.outputsc.packaging()+self.outputdst.packaging()
    
    def doublesha256(self):
        s=self.input.tostr()+self.outputsc.tostr()+self.outputdst.tostr()
        return doubleSHA256(s)
    
    def packaging(self):
        return self.input.packaging()+self.outputsc.packaging()+self.outputdst.packaging()


# In[7]:


class Blockheader:
    
    def __init__(self):
        self.version="1.0"
        self.prevhash=0
        self.merklehash=0
        self.timestamp=int(time.time())#timestamp保留的是：创建此块头时的时间戳
        self.difficultytarget=0 #挖矿难度值目标
        self.nounce=0 #挖矿创建的随机值，这个随机值的选取要符合难度值目标
    
    def calculate_hash(self):#计算这个头部得出的hash值
        s=str(str(self.version)+str(self.prevhash)+str(self.merklehash)
              +str(self.timestamp)+str(self.difficultytarget)+str(self.nounce))
        x = hashlib.sha256()
        x.update(s.encode())
        return str(x.hexdigest())
    
    def verifynounce(self):
        s=str(str(self.version)+str(self.prevhash)+str(self.merklehash)
              +str(self.timestamp)+str(self.nounce))
        x = hashlib.sha256()
        x.update(s.encode())
        res=str(x.hexdigest())
        if int(res,16)<self.difficultytarget:
            return True #满足条件
        else:
            return False
    
    def packaging(self):
        return str(str(self.version)+'\n'+str(self.prevhash)+'\n'+str(self.merklehash)+'\n'
              +str(self.timestamp)+'\n'+str(self.difficultytarget)+'\n'+str(self.nounce)+'\n')
        


# In[8]:


class Block:
    
    
    def __init__(self):#header的nounce值是矿工给定的
        self.num=0#此块在区块链中的序号
        
        self.head=Blockheader()
        self.transcounter=0 #转账记录的数量
        self.transhead=None #转账记录list的头指针
      
        self._next=None
        
        self.blocksize=sys.getsizeof(self)
    
    def addtrans(self,newtransaction):#向区块中增加交易记录，不限制条数
        '''
        if(self.transcounter==4):
            print("This block is already full")
            return False
        '''
        
             
        item=newtransaction
        
        if not self.transhead:#此区块中没有交易数据
            self.transhead=item
            self.transcounter=1
            
        else:
            node=self.transhead
            while node._next:
                node=node._next
            node._next=item
            self.transcounter+=1
         
        print("Transaction added successfully\n")
        return True
    
    
    '''
    def update_hash(self):#在此区块头修改之后更改下一个区块头存放的prevhash
        item=self
        while item._next:#要一直更改prevhash直到区块链的最后一个
            item._next.head.prevhash=item.head.calculate_hash()
            item=item._next
            
        #如果被修改的区块是最后一个？？？
    '''
    
    
    def calculate_merklehash(self):#计算merkelhash,因为交易记录只有可能增加不可能删除，所以忽略没有转账记录的情况
        #这个函数被调用时，transcounter必定大于等于4
        node=self.transhead
        h=Merklenode(node.doublesha256())
        node=node._next
        while node:
            h.addnode( node.doublesha256() )
            node=node._next

        c=self.transcounter
            
        while c!=1:#一直循环到h只有一个元素，即根节点
            p=h
            while p:#p不为None
                q=p._next
                if not q:#q为None时跳出这一层循环
                    break
                p.bi_merge(q.hashvalue)
                p._next=q._next#删去q
                p=p._next
                c-=1
                
        
        return h.hashvalue
    
    def update_merklehash(self):#生成新块时计算merklehash
        self.head.merklehash=self.calculate_merklehash()
        
        
    def verifynounce(self,oldE):
        if(self.num%2016):#维持旧的难度目标
            self.head.difficultytarget=oldE
        else:#update difficultytarget
            tarnum=self.num-2016
            
            self.head.difficultytarget=oldE*(self.head.timestamp-0)/1209600 #1209600秒=14天
            
        #return self.head.verifynounce()
        
        return True
        
    def addblock(self,newblock):
        if(newblock.transcounter<4):
            print("Not enough transactions in this block")
            return False
        node=self
        while node._next:
            node=node._next
        newblock.num=node.num+1
        newblock.head.prevhash=node.head.calculate_hash()#新结点保存区块链最后一个节点的header hashvalue
        newblock.blocksize=sys.getsizeof(self)#更新blocksize
        newblock.update_merklehash()#更新merklehash
        
        #验证新块符合要求,即找到适合的nounce
        if(newblock.verifynounce(node.head.difficultytarget)==False):
            print("Block is not valid")
            return False
        
        node._next=newblock  
        print("Block added successfully")
        return True #成功在区块链的末尾加入新块
    
    def givenounce(self,n):#对于矿工来说给nounce值
        self.head.nounce=n



# In[9]:


#网络部分

def broadcast_newblock(node):#生成新块要广播出去   
    return True

def recieve_newblock():#收到消息，更新本地区块链消息
    return True


# In[10]:


def makeblock(num,b_size,ver,preh,merh,t_stamp,E,n,tc,t_head):
    node=Block()
    node.num=num
    node.blocksize=b_size
    node.head.version=ver
    node.head.prevhash=preh
    node.head.merklehash=merh
    node.head.timestamp=t_stamp
    node.head.difficultytarget=E
    node.head.nounce=n
    node.transcounter=tc
    node.transhead=t_head
    return node

def addtoblock(B,Thead):
    node=Thead
    while node:
        B.addtrans(node)
        Thead=node._next
        node._next=None
        node=Thead


# In[11]:


#本地文件部分
def write_to_file(head):#把区块链信息保存到本地文件里
    f = open('D:\\test.txt', 'w') # 若是'wb'就表示写二进制文件
    node=head
    while node:
        
        f.write(str(node.num)+"\n"+str(node.blocksize)+"\n")        
        f.write(node.head.packaging())
        
        f.write(str(node.transcounter)+"\n")
        tmp=node.transhead
        while tmp:
            f.write(tmp.packaging())
            tmp=tmp._next
        
        f.write("Block\n")
        node=node._next
    f.close()
    return True

def read_from_file(filename):
    #判断文件路径是否存在
    path = pathlib.Path(filename)
    if(path.is_file()==False):
        print("Filename wrong")
        return None
    file = open(filename, 'r')
    
    flag="Block"
    count=0
    head=None
    t_head=None #transhead
    t_count=0
    
    for line in file.readlines():
        line=line.strip('\n') #去除换行符
        #print(line)
        if(line==flag):#到了新块的时候了
            newblock=makeblock(num,b_size,ver,preh,merh,t_stamp,E,n,tc,t_head)
            if(head==None):
                head=newblock
            else:
                head.addblock(newblock)
            t_head=None
            count=0
            t_count=0
        elif(count==0):
            num=int(line)#block number
            count+=1
        elif(count==1):
            b_size=int(line)#blocksize
            count+=1
        elif(count==2):
            ver=line #version
            count+=1
        elif(count==3):
            preh=line #prevhash
            count+=1
        elif(count==4):
            merh=line #merklehash
            count+=1
        elif(count==5):
            t_stamp=int(line) #timestamp
            count+=1
        elif(count==6):
            E=int(line) #difficultytarget
            count+=1
        elif(count==7):
            n=int(line) #nounce
            count+=1
        elif(count==8):
            tc=int(line) #transcounter
            count+=1
        #count==9 录入交易信息
        elif(t_count==0):
            a,p,f=map(str,line.split('\t'))
            a=int(a)
            f=int(f)
            tinput=document(a,p,f)
            t_count+=1
        elif(t_count==1):
            a,p,f=map(str,line.split('\t'))
            a=int(a)
            f=int(f)
            toutsc=document(a,p,f)
            t_count+=1
        else:#t_count==2
            a,p,f=map(str,line.split('\t'))
            a=int(a)
            f=int(f)
            toutdst=document(a,p,f)
            t_count=0
            newtrans=Transaction(tinput,toutsc,toutdst)
            if not t_head:#t_head为空
                t_head=newtrans
            else:
                tmp=t_head
                while tmp._next:
                    tmp=tmp._next
                tmp._next=newtrans
    
    file.close()
    return head


# In[12]:


def UTXOgenerate(head):#给定区块链，生成UTXO池
    blocknode=head
    UTXO=None
    while blocknode:
        
        tnode=blocknode.transhead
        while tnode:
            if(tnode.outputsc.flag==0):
                if not UTXO:
                    UTXO=tnode.outputsc
                else:
                    UTXO.adddocument(tnode.outputsc)
            if(tnode.outputdst.flag==0):
                if not UTXO:
                    UTXO=tnode.outputdst
                else:
                    UTXO.adddocument(tnode.outputdst)
            tnode=tnode._next
        
        blocknode=blocknode._next
    
    return UTXO

def updateUTXO(utxo,newtrans):
    prenode=None
    node=utxo
    while node:#删老的
        if(node.flag!=0):
            if not prenode:#prenode为None,说明删掉的是头结点
                utxo=node._next
                node._next=None
                node=utxo
            else:
                prenode._next=node._next
                node._next=None
                node=prenode._next
        else:
            prenode=node
            node=node._next
        
    #加新的,此时prenode是utxo链的最后一个节点
    node=newtrans
    while node:
        if(node.outputsc.amount!=0):
            if not utxo:
                utxo=node.outputsc
            else:
                utxo.adddocument(node.outputsc)
        else:#输出是0，没有存在于utxo池的意义
            node.outputsc.flag=1
        
        if(node.outputdst.amount!=0):
            if not utxo:
                utxo=node.outputdst
            else:
                utxo.adddocument(node.outputdst)
        else:#输出是0，没有存在于utxo池的意义
            node.outputdst.flag=1
          
        node=node._next
        
    return utxo

def getfirstrelated(root,name):#从root节点开始，返回第一个名字是name的节点
    node=root
    while node:
        if(node.people==name):
            node.flag=1
            return node
        node=node._next
    return None


def getbalance(utxo,name):#得到名字是name的人的余额
    node=utxo
    res=0
    while node:
        if(node.people==name):
            res+=node.amount
        node=node._next
    return res


# In[13]:


def maketransaction():
    print("Please input transaction information:\n")
    privatekey=input("sender privatekey:  ")#密码
    publickey=input("sender public key:  ")#账号
    senderaddr=input("sender:  ")#用户名
    amount=input("amount:  ")
    receiveraddr=input("receiver:  ")
    transmsg=senderaddr+"\t"+amount+"\t"+receiveraddr
    transhash=generate_signature(privatekey,transmsg)
    t=verifytransender(publickey,transmsg,transhash)
    return t


# In[14]:


def gen_key():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    return private_key, public_key

def new_keypair():
    privatekey, public_key = gen_key()
    private_key = binascii.hexlify(privatekey.to_string()).decode('ascii')
    public_key = binascii.hexlify(public_key.to_string()).decode('ascii')
    f = open('D:\\useraccount.txt', 'w') # 若是'wb'就表示写二进制文件
    f.write("Private_key:"+str(private_key))
    f.write("\nPublic_key:"+str(public_key))
    f.write("\nAddress:"+str(getaddress(public_key)))
    f.close()
    return private_key, public_key


# In[15]:


def generate_signature(privkey, data):
    data = data.encode('utf-8')
    sign_key = ecdsa.SigningKey.from_string(bytes.fromhex(privkey), curve=SECP256k1)
    signature = Signature.gen_ECDSA_sig(sign_key, data)
    # print(signature)
    return signature

def verify_signature(pubkey,data,sign):
    data = data.encode('utf-8')
    ver_key = ecdsa.VerifyingKey.from_string(bytes.fromhex(pubkey), curve=SECP256k1)
    if Signature.verify_ECDSA_sig(ver_key, data, sign):        
        print("验证签名通过")
        
    return Signature.verify_ECDSA_sig(ver_key, data, sign)


class Signature:

    @staticmethod
    def gen_ECDSA_sig(privkey, inputs):
        return privkey.sign(inputs)         # ecdsa自带的

    @staticmethod
    def verify_ECDSA_sig(pubkey, data, signature):
        return pubkey.verify(signature, data)
    

def getaddress(publickey):
    publickey = "".join([str("04"), str(publickey)])
    publickey_hash = hash_pk(publickey)
    version_payload = "".join(["00", str(publickey_hash)])  # 加上0x00
    Checksum = checksum(version_payload)  # 两次哈希计算
    full_payload = "".join([str(version_payload), str(Checksum)])  # 新的校验和
    address = b58encode(full_payload).decode('ascii')  # 上一步结果进行base58编码
    # print(address)
    return address

def hash_pk(public_key):
    # 先判断类型
    if not isinstance(public_key, (bytes, bytearray, str)):
        raise TypeError("pub 类型错误，需要str 或者bytes类型！")
    if isinstance(public_key, str):
        public_key = public_key.encode("utf-8")
        # sha256
    publickey_sha256 = hashlib.sha256(public_key).hexdigest()
    # publickey_sha256 = str(publickey_sha256)
    # RIPEMD160
    m = hashlib.new("ripemd160", publickey_sha256.encode("utf-8"))
    ripemd160_pubkey = m.hexdigest()
    # print(ripemd160_pubkey)
    return ripemd160_pubkey

def checksum(payload):  # 计算双哈希并且取前四个字节
    if not isinstance(payload, (bytes, bytearray, str)):
        raise TypeError("payload 类型错误，需要str 或者bytes类型！")
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    first_sha = hashlib.sha256(payload)
    first_sha = first_sha.hexdigest()
    second_sha = hashlib.sha256(first_sha.encode('utf-8'))
    second_sha = second_sha.hexdigest()
    return second_sha[:8]  # 取前四个字节
    


# In[16]:


def verifytransender(publickey,transmsg,transhash):
    if verify_signature(publickey,transmsg,transhash)==False:
        print("Publice key and Private key are not matched.")
        return None
    s,a,r=map(str,transmsg.split('\t'))
    pukaddr=getaddress(publickey)
    if(pukaddr==s):
        t=transaction(s,int(a),r)
        return t
    else:
        print("Identification authentification wrong")
        return None


# In[18]:


if __name__=='__main__':
    h=read_from_file("D:\\test.txt")
    utxo=UTXOgenerate(h)
    print("What do you want to do?")
    print("Generate a new wallet:0")
    print("Having a transaction:1")
    choice=input("Please input your choice:  ")
    choice=int(choice)
    newb=Block()
    if(choice==0):
        new_keypair()
        print("Please refer to the D:\\useraccount.txt to see details.")
    elif(choice==1):
        
        while(h.addblock(newb)==False):#如果不能成功生成新块
            print("Please give more transactions to update blockchain")
            t=maketransaction()
            if not t:#t为None
                #print("t为None")
                continue
            
            op=t.toTrans(utxo)
            utxo=updateUTXO(utxo,op)#更新utxo池
        
            addtoblock(newb,op)
            
        newb=Block()#更新块
        write_to_file(h)
    else:
        print("sorry, your choice is not valid.")
        
    

