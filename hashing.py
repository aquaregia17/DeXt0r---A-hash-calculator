import hashlib
print("Convert text to md5:")
print("Convert text to sha256:")
print("Convert text to sha512")
print("Convert text to blake2b ")
print('Convert Text to sha3_256:')
print('Convert text to sha3_512')
n = int(input("Enter the choice of script to convert:"))
if n==1:
    str = input("Enter your string to convert into hash")
    result = hashlib.md5(str.encode())
    print("The hexadecimal hash is :",end="")
    print(result.hexdigest())

elif n==2:
    str = input("Enter your string to convert into hash")
    result = hashlib.sha256(str.encode())
    print("The hexadecimal hash is:",end="")
    print(result.hexdigest())

elif n==3:
    str = input("Enter your string to convert into hash")
    result = hashlib.sha512(str.encode())
    print("The hexadecimal hash is :",end="")
    print(result.hexdigest())

elif n==4:
    str = input("Enter your string to convert into hash")
    result = hashlib.blake2b(str.encode())
    print("The hexadecimal hash is :",end="")
    print(result.hexdigest())

elif n==5:
    str=input("Enter your string to convert into hash")
    result = hashlib.sha3_256(str.encode())
    print("The hexadecimal hash is:",end="")
    print(result.hexdigest())

elif n==6:
    str=input("Enter your string to convert into hash")
    result = hashlib.sha3_512(str.encode())
    print("The hexadecimal hash is:",end="")
    print(result.hexdigest())
print("Program ended successfully")