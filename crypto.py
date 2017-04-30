import base64
import requests
import urllib3

#http://padding-oracle.cleverapps.io/
#https://github.com/mpgn/Padding-oracle-attack

def main():

	previous_block = bytearray.fromhex("0000000000000000")

	digitsFound = False

	message = ("0eb32a58142e7af30b73ddada9412ed12ff7b13c8df1916ec18c9595f561a2ea486bb1d91033d3bf63c501972cf"
	"8d09440b1b9b2210d02cc429c537a70418de1a1e2e6d26ea5ed4f1c9c1d30790a7ac09c2a3367548dfcd146d825c052b108fdd"
	"0a672fe4b89a5084a4eab61fdb12f8e47b79b12b1acc9482447d303dd57acb9b68bff1ca6ab41f13bfeb4a430455195d3f81b8"
	"5601d96abb3cc7f4ee1debb914a1764877ab4b4f7dfd5e108a0bba818d076ee75b40485e9cee8a0e9579803ba02843521ea3de"
	"680391d406913741ec329c1506c7cb94c54a1d79e7fa505b8af0750e688e03820c326e8aa51157c021722f7e22f8d733f24dec"
	"e8e4d21b876ecb18773842c635b1ea78361e193133b955169c80ee3a57f1d6d49a939ee9f93ba2b1a137cbc5aa63e68f284cf5"
	"30ed55556e747305327d51ae682ed06720cdb49c1d3df741fc8aa774bab6defcfbf30ff5e47de0a61b1e6d0b85ee9907942e66"
	"a9d5fc2aea99cfe0782d3d766a630c4809767d237c0d583271f4ea1d11a7574da3b025c03cb671441e2d50cbff89923622d742"
	"24acf59b8fe09f0edc24b1735253242bd44b982309f7ab7d153e19506a02f5e5387e4523dbd200ef1e7c9ef01c72d0f3271201"
	"d8fe69863173b2f009ebd2b16e08f55830f21d99ff6877b001305a6d0fab3150ef10eba12d1e00bae1b99f3e702dd9c04c5c47"
	"e6ce6c196886e52e7d5cb8f8921568c32eac7967406ab48")


	for b in range(0,int(len(message)/16)):

		block1 = "0000000000000000"
		block2 = message[b*16:b*16+16]

		print("#### BLOCK " + str(b) + " : " + block2 + " ####")

		for z in reversed(range(1,9)):
			total = ""
			print("z = " + str(z))

			for i in range(16):

				if digitsFound:
					print("breaker")
					digitsFound = False
					break

				iDec = '{0:x}'.format(i)

				for y in range(16):
					yDec = '{0:x}'.format(y)

					block1 = block1[:z*2-2] + iDec + yDec + block1[z*2:]

					full = block1 + block2
					print(full)

					byted = bytearray.fromhex(full)
					#print(byted)

					encoded64 = base64.b64encode(byted).decode('ascii')
					#print(encoded64)
					try:
						r = requests.post("http://padding-oracle.cleverapps.io/", encoded64)
					except requests.exceptions.ConnectionError as error:
						print("cancer")
					#print(r.text)

					if r.text == "1":
						print("success : " + block1)
						block1 = update_padding(bytearray.fromhex(block1), z-1)
						print("success : " + block1)
						digitsFound = True
						break
		print(block1)
		print(block2)
		decrypted = plain(xor(bytearray.fromhex(block1), bytearray.fromhex("0000000000000000")))
		print("DECRYPTED : " + decrypted.decode("utf-8"))
		block2 = block1


def update_padding(x, last_index):
    for index in range(last_index, 8):
        x[index] = x[index] ^ 8 - last_index ^ (9 - last_index)
    return ''.join('{:02x}'.format(y) for y in x)

def xor(array1, array2):
    result = bytearray()
    for i in range(0, 8):
        result.append(array1[i] ^ array2[i])
    return result

def plain(x):
    return xor(x, bytearray.fromhex("0808080808080808"))


if __name__ == "__main__":
		main()

	
