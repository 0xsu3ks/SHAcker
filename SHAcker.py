from pwn import *
from colored import fg, attr
import sys
import string

#set pretty colors
red = (fg(1), attr(0))
green = (fg(40), attr(0))
yellow =  (fg(226), attr(0))

#check if user passed correct amount of arguments
if len(sys.argv) != 3:
	print("%s [!] Error: Invalid amount of arguments %s" % (fg(1), attr(0)))
	print("[+] Usage: {} [SHA-256 hash] [wordlist] [+]".format(sys.argv[0]))
	exit()

sha256_hash = sys.argv[1]
wordlist = sys.argv[2]

#check if user entered a correct hash
def check_input(sha256_hash):
	if len(sha256_hash) != 64:
		print("%s [!] Error: Hash length mismatch %s" % (fg(1), attr(0)))
		exit()
	elif all(c in string.hexdigits for c in sha256_hash) == False:
		print("%s [!] Error: Hash contains invalid character %s" % (fg(1), attr(0)))
		exit()
	elif len(sha256_hash) == 0:
		print("%s [!] Error: No hash entered %s" % (fg(1), attr(0)))

check_input(sha256_hash)

#convert hash to lowercase
sha256_hash = sha256_hash.lower()
print("%s [+] HASH: {} %s".format(sha256_hash) % (fg(226), attr(0)))

with log.progress("Attemping to crack: {}!\n".format(sha256_hash)) as p:
	with open(wordlist, "r", encoding="latin-1") as password_list:
		for password in password_list:
			password = password.strip('\n').encode("latin-1")
			password_hash = sha256sumhex(password)
			p.status("[+] Cracking....\n[+] {}:{}".format(password.decode("latin-1"), password_hash))
			if password_hash == sha256_hash:
				p.success("%s PASSWORD FOUND! :: {} :: %s".format(password.decode("latin-1")) % (fg(40), attr(0)))
				exit()
		p.failure("%s [X] NO PASSWORD FOUND %s" % (fg(1), attr(0))) 