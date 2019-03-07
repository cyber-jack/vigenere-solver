# -*- coding: cp1252 -*-

#Imports Necessary Libraries
from collections import Counter
import string
import vigenereTools
import subsolve

#This function calculates the index of coincidence
def indexOfCoincidence(cipher_text):
    N            = len(cipher_text)
    freqs        = Counter(cipher_text)
    alphabet     = map(chr, range(ord('A'),ord('Z')+1)) #converts letters to numbers
    freqsum      = 0.0

    #This for loop adds letter frequencies multiplied by letter frequency minus one
    for letter in alphabet:
        freqsum += freqs[letter] * (freqs[letter]-1)

    IC = freqsum / (N*(N-1))
    return IC
    
#This functions estimates the key length using friedmans first formula
def friedmanKeyLen1(n,i):
    keyLen = ((0.027*n)/((n-1)*i-(0.038*n)+0.065))
    return keyLen

#This functions estimates the key length using friedmans second formula        
def friedmanKeyLen2(i):
    keyLen = (0.065-0.038)/(i-0.038)
    return keyLen

#This function calculates the average index of coincidence for each key
#This function returns the key with maximum average index of coincidence
def averageIC(ciphered, max_key):
    all_avgIC={} #dictionary to store all average ICs
    for key_len in range(2,max_key): #This for loop iterates through the key lengths
        iCList =[] #List of sequence ICs' for each key length
        for j in range(0,key_len):
            sequence =""
            for i in range(j, (len(ciphered)), key_len): #generates sequences for each key length
                sequence+= ciphered[i]
            iCList.append(indexOfCoincidence(sequence)) #adds the IC to IC list
        avgIC = sum(iCList)/len(iCList) #calculates the average IC using the IC List
        all_avgIC[key_len]=avgIC #Stores average IC with corresponding key into a dictionary

    maxIC = max(all_avgIC, key=all_avgIC.get) #gets key corresponding to maximum avg IC 


    #asks user if they want to print average IC table
    avgICprint = raw_input("Would you like to print average IC table?(y/n)")
    while avgICprint not in ['Y','y','N','n','']:
        print "Please enter Y or N"
        avgICprint = raw_input("Would you like to print average IC table?(y/n)")
        
    if avgICprint in ['y','Y','Yes','yes']:
        print "Period\tAvg IC"
        for k , v in all_avgIC.iteritems(): # iterating avgIC dictionary
            print k,"\t", v
    
    return maxIC #returns key with max average IC

#Helps calculate kaisiski key length  
def kaisiskiKeyLen(kaisiski):
    if kaisiski[0]*kaisiski[1]==kaisiski[2]:
        return kaisiski[2]
    else:
        return kaisiski[0]


#This function shifts the sequences of the chosen key length 26 times around the alphabet
#then it calculates the chi square value of the shifted sequences and returns the shift value
#that corresponds to the smallest chi square value 
def caesarCracker(message):
    caesarTranslated={}
    for key in range(0, 26): #All 26 shifts
        translated=''
        for symbol in message:
            num = ord(symbol)
            num -= key
            if num > ord('Z'):
                num -= 26
            elif num < ord('A'):
                num += 26
            translated += chr(num)
        chi = calculateCHI(translated)#calculates the chi square value for the shifted sequence
        caesarTranslated[key]=chi #adds the chi squeare value to chi square dictionary

        #chooses smallest chi square value from the dictionary
        minCHI = min(caesarTranslated, key=caesarTranslated.get)
        
    #for k , v in caesarTranslated.iteritems(): # iterating caesarTranslated dictionary
       # print k,"\t", v
        
    return minCHI #returns smallest chi square value for the sequence


#A function that calculates the chi square value
def calculateCHI(text):
    text=text.lower()
    #Letter frequencies in english language
    e_frq= [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015,
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749,
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758,
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074]
    expct_count={}
    for each in set(text):
        q=ord(each)-97
        expct_count[each]=e_frq[q]*len(text)
    chi_sqr=sum(((text.count(a)-expct_count[a])**2)/expct_count[a] for a in set(text))
    return chi_sqr

#A function that calculates the sequences of a chosen key lengths, shifts each sequence
#using the caesarCracker function, adds all the shift values into an array
#then it translates that array into letters and returns it
#the returned array is the possible polyalphabetic cipher key
def solveUsingCHI(period, ciphered):
    solution=[]
    for j in range(0,period):
            sequence =""
            for i in range(j, (len(ciphered)), period):
                sequence+= ciphered[i]
            solution.append(caesarCracker(sequence))
    for itm in range(0,len(solution)):
        solution[itm] = chr(solution[itm]+ord('A'))
    return solution

#A function borrowed from http://inventwithpython.com/vigenereCipher.py
#This function decodes a vigenere cipher knowing the key
def translateMessage(key, message, mode):
    translated = [] # stores the encrypted/decrypted message string
    LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    keyIndex = 0
    key = key.upper()

    for symbol in message: # loop through each character in message
        num = LETTERS.find(symbol.upper())
        if num != -1: # -1 means symbol.upper() was not found in LETTERS
            if mode == 'encrypt':
                num += LETTERS.find(key[keyIndex]) # add if encrypting
            elif mode == 'decrypt':
                num -= LETTERS.find(key[keyIndex]) # subtract if decrypting

            num %= len(LETTERS) # handle the potential wrap-around

            # add the encrypted/decrypted symbol to the end of translated.
            if symbol.isupper():
                translated.append(LETTERS[num])
            elif symbol.islower():
                translated.append(LETTERS[num].lower())

            keyIndex += 1 # move to the next letter in the key
            if keyIndex == len(key):
                keyIndex = 0
        else:
            # The symbol was not in LETTERS, so add it to translated as is.
            translated.append(symbol)

    return ''.join(translated)

#Main function
def main():
    #Imports the cipher from the encoded.txt file
    cipher_file  = open( 'encrypted.txt', 'rb')  
    cipheredORG  = cipher_file.read()

    #Checks if cipher text is long enough
    if len(cipheredORG)<200:
        print "Not enough cipher text \n Exiting..."
        quit()
    #Edits ciphered text to remove spaces and punctuation and change it to upper case
    ciphered= ''.join(x for x in cipheredORG if x.isalpha())
    ciphered=ciphered.upper()

    #Calculates friedmans index of coincidence
    friedman = indexOfCoincidence(ciphered)

    #English language IC and random text IC
    randomLetterProbability=[0.065, 0.038]


    print "Index of Coincidence is", friedman

    #A value of IC near 0.065 would indicate that a monoalphabetic cipher was used
    #A value of IC near 0.038 would indicate that a polyalphabetic cipher was used
    #This if statement compares the result IC to the twovalues
    if (min(randomLetterProbability, key=lambda x:abs(x-friedman))== 0.065):
        print "This suggests that a monoalphabetic cipher was used"
        print "Using a dictionary attack..."
        subsolve.main()
        raw_input("Press Enter to exit...")
    elif(min(randomLetterProbability, key=lambda x:abs(x-friedman)) == 0.038):
        print "This suggests that a polyalphabetic cipher was used."
            #Asks user for maximum key length
        max_key= raw_input("Please enter the maximum key length (default = 15) -->")
        if type(max_key) != int: #if user did not enter a value or entered some text
            max_key = 15
        
        print "Estimating key length..."
        
        #Calculates friedmans estimates of key length using the functions above
        print "Freidmans key estimation 1:", friedmanKeyLen1((len(ciphered)+0.0), friedman)
        print "Freidmans key estimation 2:", friedmanKeyLen2(friedman)
        #Estimates the key based on the kaisiski analysis
        kaisiski = vigenereTools.kasiskiExamination(ciphered)
        kaisiskiPrint = raw_input("Would you like to print the kaisiski key space?(y/n)")
        while kaisiskiPrint not in ['Y','y','N','n','']:
            print "Please enter Y or N"
            kaisiskiPrint = raw_input("Would you like to print the kaisiski key space?(y/n)")
        
        if kaisiskiPrint in ['y','Y','Yes','yes']:
            print "The kaisiski analysis suggests the following keyspace", kaisiski
            
        print "The kaisiski analysis suggests that we have a period of", kaisiskiKeyLen(kaisiski)

        #Estimates the key length based on the average IC
        maxIC = averageIC(ciphered, max_key)
        print "The average IC analysis suggests that we have a period of", maxIC

        #Asks the user to enter a key length that they see fit based on the three previous tests
        while True:
            try:
                userKeyLen = int(input("Which key length would you like to use for the CHI Square analysis?"))
            except ValueError:
                print('Invalid input. Try again.')
            except SyntaxError:
                print('Invalid input. Try again.')
            except NameError:
                print('Invalid input. Try again.')
            else:
                break

        #Passes the entered key length value to the solveUsingCHI function that returns the possible key
        key = solveUsingCHI(userKeyLen, ciphered)
        keyword= ''.join(key)
        print "Your key might be", keyword
        #Tries to decode the message using the found key
        raw_input("Press Enter to decode the message using the above key...")
        translated = translateMessage(keyword, cipheredORG, 'decrypt')
        print translated
        raw_input("Press Enter to exit...")


#What does this do?
#Answer here --> https://stackoverflow.com/questions/419163/what-does-if-name-main-do
if __name__ == '__main__':
    main()
