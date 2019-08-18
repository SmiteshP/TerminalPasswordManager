'''
VAULT -- Terminal Password Manager
	created by - Smitesh V. Patil.
	on - 22 July, 2019.

verision -- 1.0.0

Working explained:

Each user gets a .txt file created in their name in the format UserName.txt and are stored in directory where this script resides.
sha512 is used to hash and store a 'MasterPassword' in the first line of the UserName.txt file.
Data that user wishes to store is encryted using Ceasar Cipher and stored in subsiquent lines of UserName.txt

Known Bugs:

Code won't work when this file is stored in a git repo
	cause- weird output of os.walk() in checkUserName()
'''

from hashlib import sha512
import sys
import os
import getpass
import time

### Encryption Essentials ### 

# Returns hexadecimal hashed string
def get_hexdigest(MasterPassword):
	return sha512(MasterPassword.encode('utf-8')).hexdigest()

# All allowed charaters in the passwords to be stored
AllChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*?<>.,:;[]|{} _'

NumToChar = {}
CharToNum = {}

# NumToChar is dictonary with numeical keys to alphabets
# CharToNum is dictionary with alphabet as keys to corresponding numbers
for i in range(len(AllChars)):
	NumToChar[i] = AllChars[i]
	CharToNum[AllChars[i]] = i

# Generate Ceasar Key based on master password
def GenerateKey(MasterPassword):
	Input = [i for i in MasterPassword]
	Output = [CharToNum[i] for i in Input]
	return Output

# Encryprs Password by applying Ceasar shift according to Master Password on the password to be stored
def EncryptPassword(MasterPassword, password):
	MasterPassword = GenerateKey(MasterPassword)
	password = [i for i in password]
	password = [CharToNum[i] for i in password]
	
	for i in range(len(password)):
		password[i] = (password[i] + MasterPassword[i%len(MasterPassword)])%len(AllChars)

	password = [NumToChar[i] for i in password]

	str1 = ''
	return str1.join(password)

# Decrypts Password 
def DecryptPassword(MasterPassword, password):
	MasterPassword = GenerateKey(MasterPassword)
	MasterPassword = [-i for i in MasterPassword]
	password = [i for i in password]
	password = [CharToNum[i] for i in password]
	
	for i in range(len(password)):
		password[i] = (password[i] + MasterPassword[i%len(MasterPassword)])%len(AllChars)

	password = [NumToChar[i] for i in password]

	str1 = ''
	return str1.join(password)

###

### File Handling ###

# Check if username is correct 
# Return Code:
# 0 -> file does not exist
# 1 -> file exists 
# 2 -> invalid user name
def checkUserName(UserName):
	if UserName == None:
		return 2

	path = os.getcwd()
	fileName = UserName + '.txt'

	for _, _, files in os.walk(path):
		pass

	UserNameExist = 1 if fileName in files else 0

	return UserNameExist

# Checks if the user entered correct master password
# Return Code:
# 0 -> Password Mis-Match
# 1 -> Password Match 
def checkMasterPassword(UserName, MasterPassword):
	hashed_MPswd = get_hexdigest(MasterPassword)
	fileName = UserName + '.txt'

	file = open(fileName)

	lines = []
	for line in file:
		lines.append(line)

	if ((hashed_MPswd + '\n') == lines[0]) or (hashed_MPswd == lines[0]):
		return 1
	else:
		return 0

	file.close()

# Creates .txt file for the user
def createUser(UserName, MasterPassword):
	fileName = UserName + '.txt'
	hashed_MPswd = get_hexdigest(MasterPassword)

	file = open(fileName, 'w')
	file.write(hashed_MPswd)
	file.write('\nSnooping Protection Activated (-_-)')
	
	file.close()

# Deletes .txt file for the said user if master password is valid
# Return Code:
# 0 -> deletion success
# 1 -> deletion unseccessful
def remUser(UserName, MasterPassword):
	fileName = UserName + '.txt'
	
	if checkMasterPassword(UserName, MasterPassword):
		os.remove(fileName)
		print('Account deletion succesfull.')
		return 0
	else:
		print('The master password does not match. Account deletion failed!')
		return 1

# Adds Encrypted line to user file
def addLine(UserName, MasterPassword):
	newLine = input('Enter line to be added: ')
	fileName = UserName + '.txt'

	newLine = EncryptPassword(MasterPassword, newLine)
	newLine = '\n' + newLine

	file = open(fileName, 'a')
	file.write(newLine)
	
	file.close()

# Delete a specific line
def delLine(UserName, MasterPassword, lineNo):
	fileName = UserName + '.txt'
	file = open(fileName, 'r')

	fileData = []
	# last line is treated differently as deleting it should not leave a '\n' on the new last line.
	if int(lineNo) != len(returnReadableLines(UserName, MasterPassword)):
		for line in file:
			fileData.append(line)

		file.close()

		del fileData[int(lineNo) + 1]

		file = open(fileName, 'w')

		for line in fileData:
			file.write(line)

		file.close()
	else:
		for line in file:
			fileData.append(line)

		file.close()

		del fileData[int(lineNo) + 1]
		tempStr = fileData[-1]
		fileData[-1] = tempStr[:-1]

		file = open(fileName, 'w')

		for line in fileData:
			file.write(line)

		file.close()

# Returns decrypted data
def returnReadableLines(UserName, MasterPassword):
	fileName = UserName + '.txt'

	file = open(fileName, 'r')
	lines = []
	for line in file:
		lines.append(line)

	# this bit is for removing '\n' at the end of every line (except for the last line)
	linesNoEsc = []
	tempLine = None
	
	for line in lines[:-1]:
		linesNoEsc.append(line[:-1])

	linesNoEsc.append(lines[-1])
	
	# discard first two lines
	linesToDecrypt = linesNoEsc[2:]

	# decrypt the lines
	readableLines = []
	for line in linesToDecrypt:
		readableLines.append(DecryptPassword(MasterPassword, line))

	file.close()
	return readableLines

# Prints file data
def printFileData(UserName, MasterPassword):
	lines = returnReadableLines(UserName, MasterPassword)
	if len(lines) != 0:
		print('='*30)
		for i in range(len(lines)):
			print(str(i+1) + ':', lines[i])
		print('='*30, '\n')
	else:
		print('Nothing here!\n')

###

### Terminal UI ###

# Initial greetings (only 5 invalid tries allowed) 
# Return code:
# 0 -> login
# 1 -> signup
# 2 -> delete account
def StartUp(level):
	if (level > 5):
		sys.exit()

	UserOP = input('Enter=> (l)-login, (s)-sign up, (z)-delete account, (x)-escape : ')
	print('')

	if UserOP == 'l':
		return 0
	elif UserOP == 's':
		return 1
	elif UserOP == 'z':
		return 2
	elif UserOP == 'x':
		sys.exit()
	else:
		return StartUp(level + 1)

# Function for loging in existing user
# Return Code:
# 0 -> login success
# 1 -> User name does not exist
# 2 -> incorrect master password
def login():
	print('\nEnter your login credentials: \n')
	UserName = input('Enter your username: ')
	if checkUserName(UserName):
		MasterPassword = getpass.getpass('Enter your Master Password: ')
		print('')

		# adding sleep to slow down brute force attack on Master Password.
		time.sleep(1)

		if checkMasterPassword(UserName, MasterPassword) == 0:
			print('Incorrect master password\n')
			return 2, None, None
		else:
			return 0, UserName, MasterPassword

	else:
		print('User name does not exist\n')
		return 1, None, None

# Sign up a new user
def signUp():
	print('\n', 'Welcome to the VAULT!', '\n')

	NewUserName = input('Enter a UserName you want: ')
	RepeatFlag = 0
	while(checkUserName(NewUserName)):
		if RepeatFlag > 5:
			sys.exit()
		print('Sorry the username you requested has already been taken or is invalid\n')
		NewUserName = input('Enter a UserName you want: ')
		RepeatFlag += 1

	print('UserName Valid\n')

	passwordMatchFlag = 1
	RepeatFlag = 0
	while(passwordMatchFlag):
		if RepeatFlag > 5:
			sys.exit()
		password = getpass.getpass('Choose a Master Password for your account: ')
		if password == getpass.getpass('Confirm your password: '):
			passwordMatchFlag = 0
		else:
			print('Passwords did not match, Try again\n')
			RepeatFlag += 1

	print('\nSetting up your account! Just a moment.')

	createUser(NewUserName, password)

	print('\nAccount Created! You will need to login to your account to use it :)\n\n')

###

### Main ###

print('VAULT  -verision 1.0.0\n')

while(1):
	UserOP = StartUp(0)

	if UserOP == 0:
		loginStatus, UserName, MasterPassword = login()
		if loginStatus == 0:
			fileOP = None
			while(fileOP != 'x'):
				print('\nShowing your existing data:\n')
				printFileData(UserName, MasterPassword)
				fileOP = input('Enter: (a)-addline, (d)-delete line, (x)-log out : ')
				if fileOP == 'a':
					addLine(UserName, MasterPassword)
				elif fileOP == 'd':
					lineNo = input('Enter the number corresponding to the line: ')

					if int(lineNo) > len(returnReadableLines(UserName, MasterPassword)):
						print('line does not exist.')
					elif int(lineNo) < 1:
						print('line does not exist')
					else:
						delLine(UserName, MasterPassword, lineNo)
		else:
			continue
	
	elif UserOP == 1:
		signUp()

	elif UserOP == 2:
		print('')
		UserName = input('Enter UserName: ')
		if checkUserName(UserName) == 1:
			MasterPassword = input('Enter MasterPassword: ')
			print('')
			Confirm = input('Are you sure you want to delete your account. All your data will be permanently lost. [Y]/n :')
			if (Confirm == 'y') or (Confirm == 'Y'):
				remUser(UserName, MasterPassword)
				print('We are sorry to see you leave :(')
				print('')
		else:
			print('This UserName does not have a account.\n')

###