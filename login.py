#!/usr/bin/env python3
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from getpass import getpass
from passlib.hash import pbkdf2_sha256



def login_user(usr):
    special_characters = "!@#$%^&*()-+?_=,<>/"
    for i in range(0,3):
        password =  getpass()
        with open("database.txt","r+") as f:
            data = f.readlines()
            user_exists = False
            for line in data:
                data_line = line.strip().split("\t")
                if(len(data_line) >=3):
                    if(usr == data_line[0]):
                        user_exists = True
            if(not user_exists):
                print("Username or password incorrect.")
            else:
                #u ovom trenutku znamo da je user unutra pa mu ispitamo prvo jel lozinka dobra
                for line in data:
                    data_line = line.strip().split("\t")
                    if(len(data_line) >=3):
                        if(usr == data_line[0]):
                            salt = bytes.fromhex(data_line[2])
                            hashed_password = data_line[1]
                            hashed = pbkdf2_sha256.hash(password, rounds=100000, salt=salt)
                            if(hashed != hashed_password):
                                print("Username or password incorrect.")
                            else:
                                if(data_line[3] == "T"):
                                    special_characters = "!@#$%^&*()-+?_=,<>/"
                                    new_password =  getpass("New password: ")
                                    if(password):
                                        new_re_password = getpass("Repeat new password: ")
                                        if(new_re_password):
                                            if(new_password != new_re_password):
                                                print("Password change failed. Password mismatch.")
                                                return
                                            if(len(new_password)<8) and not any(x in special_characters for x in new_password):
                                                print("Password should be at least 8 characters long and contain special character!")
                                                return
                                            else:
                                                f.seek(0)
                                                f.truncate()
                                                for line in data:
                                                    data_line = line.strip().split("\t")
                                                    if(len(data_line) >=3):
                                                        if(usr == data_line[0]):
                                                            new_salt = get_random_bytes(16)
                                                            hashed = pbkdf2_sha256.hash(new_password, rounds=100000, salt=new_salt)
                                                            f.write(usr+"\t"+hashed+"\t"+new_salt.hex()+"\t"+"F"+"\n")
                                                        else:
                                                            f.write(line)
                                                print("Login successful.")
                                                return
                                else:
                                    print("Login successful.")
                                    return
def __main__():
    if(len(sys.argv) ==2):
        username = sys.argv[1]
        if(username):
            login_user(username)
    else:
        print("not enough arguments!")

__main__()