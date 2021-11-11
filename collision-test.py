from hash import simple_hash
import random
import string

# Hash the message and check that the hash length is correct, 
# and that we have not already seen this hash from a different input
def test_collision(msg, hashes):
    msg_hash = simple_hash(msg)
    if len(msg_hash) != 16:
        print("INCORRECT LENGTH")
        return False
    if msg_hash in hashes and hashes[msg_hash] != msg:
        print("COLLISION")
        print(msg)
        print(hashes[msg_hash])
        return False
    hashes[msg_hash] = msg
    return True

# Hashes a million random strings and checks for collision as well as fixed size output
# In my testing no collision was found
def collision_test():
    hashes = {}
    for i in range(1000):
        for j in range(1000):
            randlen = random.randrange(1, 1000)
            rand_msg = ''.join(random.choices(string.ascii_uppercase + string.ascii_lowercase + string.digits, k=randlen))
            if not test_collision(rand_msg, hashes):
                return
        print((i+1)*1000)

    print(len(hashes))

# Print out a few hash examples displaying hash properties
def examples():
    print(simple_hash(""))
    print(simple_hash(" "))

    # Avalanche Effect: Changing a single byte of the input causes cascading changes that modify the entire hash
    print(simple_hash("Hello World"))
    print(simple_hash("Hello Wosld"))

    # Rearranging bytes changes the hash
    print(simple_hash("Holle Wlrod"))

    
if __name__ == "__main__":
    #collision_test()    # Takes a long time. Comment out for just some example hashes
    examples()