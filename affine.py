import sys

def egcd(a, b):
  s, t, u, v = 1, 0, 0, 1
  while b != 0:
      q = a // b
      a, b = b, a % b
      s, t, u, v = u, v, s - u * q, t - v * q
  d = a
  return d, s, t


def mod_inverse(a, m):
  d, s, t = egcd(a, m)
  if d != 1:
      raise ValueError("Inverse does not exist")
  return s % m


def validate_key(a, m=128):
  if egcd(a, m)[0] != 1:
      return False
  return True


def encrypt(inputs, a, b):
  result = bytearray()
  for val in inputs:
      encrypted_mess = (a * val + b) % 128
      result.append(encrypted_mess)
  return bytes(result)
 

def decrypt(inputs, a, b):
  inv = mod_inverse(a, 128)
  result = bytearray()
  for val in inputs:
      decrypted_mess = (inv * (val - b)) % 128
      result.append(decrypted_mess)
  return bytes(result)


def decipher(ciphertext_file, output_file, dictionary_file):
   with open(dictionary_file, 'r') as dictionary_file:
      dictionary = set(word.strip().lower() for word in dictionary_file)

   best_key_pair = None
   max_valid_words = 0
   decrypted_message = ""

   with open(ciphertext_file, 'r') as infile:
       ciphertext = infile.read()

   for a in range(1, 128):
       if validate_key(a):
           for b in range(128):
               plaintext = ''.join(chr((mod_inverse(a, 128) * (ord(char) - b)) % 128) for char in ciphertext)
               words = plaintext.split()
               valid_words = sum(1 for word in words if len(word) >= 3 and word.lower() in dictionary)

               if valid_words > max_valid_words:
                   max_valid_words = valid_words
                   best_key_pair = (a, b)
                   decrypted_message = plaintext

   with open(output_file, 'w') as outfile:
       outfile.write(f"{best_key_pair[0]} {best_key_pair[1]}\n")
       outfile.write("DECIPHERED MESSAGE:\n")
       outfile.write(decrypted_message)


if __name__ == "__main__":
  if len(sys.argv) < 2 or sys.argv[1].lower() not in ["encrypt", "decrypt", "decipher"]:
      print("Usage: python affine.py <encrypt/decrypt/decipher>")
      sys.exit(1)


  command = sys.argv[1].lower()
 
  if command == "encrypt" or command == "decrypt":
      if len(sys.argv) != 6:
          print(f"Usage: python affine.py {command} [input-file] [output-file] [a] [b]")
          sys.exit(1)
      a = int(sys.argv[4])
      b = int(sys.argv[5])
      if not validate_key(a, 128):
          print(f"The key pair ({a}, {b}) is invalid, please select another key.")
          sys.exit(1)
  elif command == "decipher":
      if len(sys.argv) != 5:
          print("Usage: python affine.py decipher [ciphertext-file] [output-file] [dictionary-file]")
          sys.exit(1)


  input_file = sys.argv[2]
  output_file = sys.argv[3]


  if command == 'encrypt':
      with open(input_file, 'rb') as file:
          inputs = file.read()
      result = encrypt(inputs, a, b)
      with open(output_file, 'wb') as file:
          file.write(result)
  elif command == 'decrypt':
      with open(input_file, 'rb') as file:
          inputs = file.read()
      result = decrypt(inputs, a, b)
      with open(output_file, 'wb') as file:
          file.write(result)
  elif command == 'decipher':
      dictionary_file = sys.argv[4]
      decipher(input_file, output_file, dictionary_file)

