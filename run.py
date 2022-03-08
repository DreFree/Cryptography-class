from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto import Random
from base64 import b64encode, b64decode
from math import ceil, floor
import sys

t=36
B_S=128     ##block size

d={"A":"10","B":"11","C":"12","D":"13","E":"14","F":"15","G":"16","H":"17","J":"18","K":"19","L":"20","M":"21","N":"22",
   "P":"23","Q":"24","R":"25","S":"26","T":"27","U":"28","V":"29","X":"30","Y":"31","W":"32","Z":"33","I":"34","O":"35",
   }
E_cipher=None
D_cipher=None
shift_val=(4,1,4,4,4,4,4,4,4,1)

def AES_ENC_INIT(key):
    global E_cipher
    #iv = Random.new().read(AES.block_size)
    E_cipher = AES.new(key, AES.MODE_OFB)
    iv = E_cipher.iv
    return iv
def AES_ENC(d):
    global E_cipher
    global B_S
    if isinstance(d,str):
        data=d.encode(encoding="UTF-8")
    elif isinstance(d,int):
        data=d.to_bytes(ceil(B_S/8),byteorder="big")
    else:
        raise ValueError("unexpected datatype",type(data))

    ct = E_cipher.encrypt(data)

    return ct
def AES_DEC_INIT(iv,key):
    global D_cipher
    D_cipher = AES.new(key, AES.MODE_OFB, iv=iv)
def AES_DEC(d):
    global D_cipher
    global B_S
    if isinstance(d,str):
        data=d.encode(encoding="UTF-8")
    elif isinstance(d,int):
        data=d.to_bytes(ceil(B_S/8),byteorder="big")
    else:
        raise ValueError("unexpected datatype",type(data))
    #data=pad(data,AES.block_size)
    pt = D_cipher.decrypt(data)
    return pt

def do_trans(data):
    global t
    global d
    global shift_val
    bn=0b0      ##this is int type in python UGHH
    
    
    for i, each in enumerate(data):
        if i==0:
            if (each.isalpha()):
                bn=int(d[each][0])
                bn=bn<<shift_val[i]
                bn+=int(d[each][1])   
        else:
            bn=bn<<shift_val[i]
            bn^=int(each)

    #bin(int.from_bytes(num,byteorder=sys.byteorder))
    bn_bytes=bn.to_bytes(ceil(t/8),byteorder="big")
    bn_str=bin(bn)[2:]
    #print(bn,type(bn), bn_str,len(bn_str),bn_bytes, type(bn_bytes))
    return bn
def padding(val):
    global B_S
    global t
   
    return val<<B_S-floor(t/2)
  
def PRF_E(data):
    global t   
    data=padding(data)
    #pad from the left to get 128 bits for AES
    F=AES_ENC(data)
    trunc_F=int.from_bytes(F,byteorder="big")%pow(2,floor(t/2))
    ## trunc based on t/2 bits
    return trunc_F

def PRF_D(data):
    global t   
    data=padding(data)
    #pad from the left to get 128 bits for AES
    F=AES_DEC(data)
    trunc_F=int.from_bytes(F,byteorder="big")%pow(2,floor(t/2))
    ## trunc based on initial size of input data 't'
    return trunc_F
def undo_trans(num):
    global d
    global shift_val
    flag=False
    s=""
    i=len(shift_val)-1
    while True:
        s=str(num%pow(2,shift_val[i]))+s
        num=floor(num/pow(2,shift_val[i]))
        i-=1
        if i<1:
            break
    num2=num%pow(2,shift_val[0])
    num1=floor(num/pow(2,shift_val[0]))
    tmp=str(num1)+str(num2)
    
    letter=None
    for key,val in d.items():
        if val==tmp:
            letter=key
    if not letter:
        raise ValueError("Couldnt map")

    return letter+s
    

def isValid(s):
    global d
    if len(s)!=10:
        return False
    weight=[1,9,8,7,6,5,4,3,2,1,1]
    sum=0
    for i, let in enumerate(s):
        if i==0:
            try:
                temp=d[let]
            except:
                return False
            sum+=int(temp[0])*weight[i]
            sum+=int(temp[1])*weight[i+1]
        else:
            if i==1:
                if let.isalpha():
                    return False
                if int(let)>1:
                    return False
            if i==9:
                if int(let)>1:
                    return False
            sum+=int(let) *weight[i+1]
           
    if sum%10==0:
        return True
    return False
def LR_E(data,key):       ## Luby Rackoff - constructions for Encryption
    global t
    global B_S

    flag=False
    count=0
    nonce=None
    if not isValid(data):
        raise ValueError("Error input format mismatch")
    iv =AES_ENC_INIT(key)
    data=do_trans(data)
    #print(data)
    left=floor(data/pow(2,int(t/2)))
    right=data%pow(2,int(t/2))
    while not flag:
        count+=1
        for i in range(3):
            if count+i!=1:
                temp=right
                right=left
                left=temp
            F_prime=PRF_E(right)
            left^=F_prime 
            
        data=left
        data=data<<floor(t/2)
        data^=right
        try:
            st=undo_trans(data)
        except:
            continue
        #print(data)
        if isValid(st):
            flag=True
    print("ENC repeat:",count)
    return st, iv


def LR_D(data,iv,key):       ## Luby Rackoff - constructions for Encryption
    global t
    global B_S
    flag=False
    count=0
    if not isValid(data):
        print("Error input format mismatch")
        return
    AES_DEC_INIT(iv,key)
    data=do_trans(data)
    #print(data)
    left=floor(data/pow(2,int(t/2)))
    right=data%pow(2,int(t/2))
    while not flag:
        count+=1
        for i in range(3):
            if count+i!=1:
                temp=right
                right=left
                left=temp    
            F_prime=PRF_D(right)
            #print(F_prime)
            left^=F_prime 
            
        data=left
        data=data<<floor(t/2)
        data^=right
        #print(data)
        try:
            st=undo_trans(data)
        except:
            continue
        if isValid(st):
            flag=True
    print("DEC repeat:",count)
    return st

def test1():
    #Transform and undo transform verification test.
    from random import randint
    global d
    for i in range(500000):
        t=randint(10,35)
        for k,v in d.items():
            if v==str(t):
                let=k
        for i in range(9):
            let+=str(randint(0,9))
        
        if isValid(let):
            print(let)
            data=do_trans(let)
            d1=undo_trans(data)
            if let!=d1:
                print("Miss-match #",i)
                print(let)
                print(d1)
                break
    print(bin(data),len(bin(data)[2:]))
    data2=bin(padding(data))[2:]
    print(data2,len(data2))

if __name__=="__main__":
    #test2()
    #quit()
    print("AES - FPE Program.")
    k=get_random_bytes(16)
    ID="A100000001"
    while True:
        try:
            ct,iv=LR_E(ID,k)     
        except ValueError as e:
            print(e)
            quit()
        print("Cypher text:",ct)
        print("IV:",iv)
        pt=LR_D(ct,iv,k)
        print("Plain-text:",pt)
        print()
        if pt==ID:
            break


