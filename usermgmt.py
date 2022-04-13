#!/usr/bin/env python3
import sys
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
import os.path
from getpass import getpass
from passlib.hash import pbkdf2_sha256



"""
5.
"""
def delete_user(usr):
    with open("database.txt","r+") as f:
        data = f.readlines()
        user_exists = False
        for line in data:
            data_line = line.strip().split("\t")
            if(len(data_line) >=3):
                if(usr == data_line[0]):
                    user_exists=True
        if(not user_exists):
            print("User "+usr+" does not exist in database!")
            return
        else:
            f.seek(0)
            f.truncate()
            for line in data:
                data_line = line.strip().split("\t")
                if(len(data_line) >=3):
                    if(usr == data_line[0]):
                        continue
                    else:
                        f.write(line)
        print("User successfully removed.")
"""
4.
"""
def change_password(usr):
    special_characters = "!@#$%^&*()-+?_=,<>/"
    password =  getpass()
    if(password):
        re_password = getpass("Repeat Password: ")
        if(re_password):
            if(password != re_password):
                print("Password change failed. Password mismatch.")
                return
            if(len(password)<8) and not any(x in special_characters for x in password):
                print("Password should be at least 8 characters long and contain special character!")
                return
            else:  
                with open("database.txt","r+") as f:
                    data = f.readlines()
                    user_exists = False
                    for line in data:
                        data_line = line.strip().split("\t")
                        if(len(data_line) >=3):
                            if(usr == data_line[0]):
                                user_exists=True
                    if(not user_exists):
                        print("User "+usr+" does not exist in database!")
                    else:
                        f.seek(0)
                        f.truncate()
                        for line in data:
                            data_line = line.strip().split("\t")
                            if(len(data_line) >=3):
                                if(usr == data_line[0]):
                                    salt = get_random_bytes(16)
                                    hashed = pbkdf2_sha256.hash(password, rounds=100000, salt=salt)
                                    f.write(usr+"\t"+hashed+"\t"+salt.hex()+"\t"+"F"+"\n")
                                    print("Password change successful.")
                                else:
                                    f.write(line)
"""
3.
"""
def force_password(usr):
    with open("database.txt","r+") as f:
        data = f.readlines()
        user_exists = False
        for line in data:
            data_line = line.strip().split("\t")
            if(len(data_line) >=3):
                if(usr == data_line[0]):
                    user_exists=True
        if(not user_exists):
            print("User "+usr+" does not exist in database!")
        else:
            f.seek(0)
            f.truncate()
            for line in data:
                data_line = line.strip().split("\t")
                if(len(data_line) >=3):
                    if(usr == data_line[0]):
                        f.write(usr+"\t"+data_line[1]+"\t"+data_line[2]+"\t"+"T"+"\n")
                        print("User will be requested to change password on next login.")
                    else:
                        f.write(line)
"""
2. stvaranje novog usera
*gledam na sve u smislu da neko pokusava nes krivo upisat ali taj dio se ne provjerava
gledamo na to da upisujemo podatke kak bi ih trebali upisivat , a brinemo samo za dio 
da lozinke budu pravilno hashirane i da nema preklapanja u njima
"""
def add_new_user(usr):
    special_characters = "!@#$%^&*()-+?_=,<>/"
    if sys.stdin.isatty():
        password =  getpass()
    else:
        password = input("Password: ")
    if(password):
        if sys.stdin.isatty():
            re_password = getpass("Repeat Password: ")
        else:
            re_password = input("Repeat Password: ")
        if(re_password):
            if(password != re_password):
                print("User add failed. Password mismatch.")
                return
            if(len(password)<8) and not any(x in special_characters for x in password):
                print("Password should be at least 8 characters long and contain special character!")
                return
            else:
                salt = get_random_bytes(16)
                hashed = pbkdf2_sha256.hash(password, rounds=100000, salt=salt)
                with open("database.txt","r+") as f:
                    data = f.readlines()
                    for line in data:
                        data_line = line.strip().split("\t")
                        if(len(data_line) >=3):
                            if(usr == data_line[0]):
                                print("User already exists in database. Change password or forcePassword!")
                                return
                    f.seek(0)
                    f.truncate()
                    for line in data:
                        f.write(line)
                    f.write(usr+"\t"+hashed+"\t"+salt.hex()+"\t"+"F"+"\n")
                    print("User "+usr+" successfully added.")
"""
1.
"""
def create_database():
    """
        provjera jel postoji .txt fajl gdje pohranjujem usere i passworde
        nije potrebno moze se samo stvoriti datoteke i u nju zapisivat bez ovoga
    """
    if(not os.path.exists("./database.txt")):
        with open("database.txt","w") as f:
            f.write("")
        return
    else:
        return

def __main__():
        """
            stvaranje baze podataka
        """
        create_database()
        """
            provjera jel imamo jos dodatna dva argumenta
        """
        if(len(sys.argv) ==3):
            command = sys.argv[1]
            username = sys.argv[2]
            if(command and username):
                if(command == "add"):
                    """DONE"""
                    add_new_user(username)
                elif(command == "passwd"):
                    change_password(username)
                elif(command == "forcepass"):
                    force_password(username)
                elif(command == "del"):
                    delete_user(username)
        else:
            print("not enough arguments!")

__main__()