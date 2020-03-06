from pwn import *

port = 9007
domain = 'pwnable.kr'

conn = remote(domain, port)
print conn.recvuntil("3 sec... -")
sleep(3)

for i in range(100):
	data = conn.recvuntil("N")
	data = conn.recv()
	print "[Server] {}".format(data)
	data = data.split(" ")
	numberOfCoin = int(data[0].split("=")[1])
	coins = [str(i) for i in range(numberOfCoin)]
	chance = int(data[1].split("=")[1])

	start = 0
	mid = numberOfCoin/2
	end = numberOfCoin

	presentArr = coins[start:mid]
	sended = " ".join(presentArr)
	ans = 0
	while chance > 0:
		print "[C={}]---------start {}, mid {}, end {}-----------".format(chance, start, mid, end)
		conn.sendline(sended)
		print "[Client] {}".format(sended)
		ans = sended
		data = conn.recv()
		print "[Server] {}".format(data)
		if int(data) % 2 == 0: # In case, not exists a counterfeit coin.
			start = mid
			mid = (mid+end)/2
		else:	# In case, exists a counterfeit coin.
			end = mid
			mid = (mid+start)/2

		if start < 0: start = 0
		elif mid > numberOfCoin: mid = end = numberOfCoin

		if start == mid or mid == end:
			print "Only one {} coin, chance={}".format(mid, chance)
			ans = mid
			sended = str(mid)
			chance -= 1
			continue

		presentArr = coins[start:mid]
		sended = " ".join(presentArr)
		chance -= 1
	
	conn.sendline(str(ans))
	print "[Client] {}".format(ans)
	data = conn.recvline(100)
	print "[Server-turn end] {}".format(data)

print "[Server] "
print conn.recv()
conn.close()
