import re
import time
import json
import base64
import hashlib
import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

class Resolver:    
    def calculate_md5(self, input_bytes) -> bytes:
        return hashlib.md5(input_bytes).digest()


    def decode_base64_array(self, encoded_str) -> bytearray:
        return bytearray(base64.b64decode(encoded_str))
    

    def get_player_js(self, player) -> str:
        '''
            Fetches player.

            Returns:
                (str): rabbitstream e4-player content
        '''
        urls = {
            "e1": "https://megacloud.tv/js/player/a/prod/e1-player.min.js",
            "e4": "https://rabbitstream.net/js/player/prod/e4-player.min.js",
            "e6": "https://rapid-cloud.co/js/player/prod/e6-player-v2.min.js",
        }
        
        req = requests.get(urls[player])
        return req.text
    

    def get_extraction_key(self, script) -> list:
        '''
            Extracts key using regex.

            Returns:
                (list): extraction key
        '''
        switch_body = script[script.rindex('switch'):script.index('partKeyStartPosition')]
        indexes = []

        for match_1 in re.finditer(r':[a-zA-Z0-9]+=([a-zA-Z0-9]+),[a-zA-Z0-9]+=([a-zA-Z0-9]+);', switch_body):
            sub_indexes = []

            for match_2 in [match_1.group(1), match_1.group(2)]:
                regex = re.compile(f'{match_2}=0x([a-zA-Z0-9]+)')
                matches = list(re.finditer(regex, script))
                last_match = matches[-1]

                if not last_match:
                    return None
                
                sub_indexes.append(int(last_match.group(1), 16))

            indexes.append([sub_indexes[0], sub_indexes[1]])

        return indexes
        
    
    def get_final_key(self, deob_key) -> list:
        '''
            Get final extraction key.

            Returns:
                (list): list of integers to get key
        '''
        current_sum = 0
        final_key = []

        for first_term, second_term in deob_key:
            first_term += current_sum
            current_sum += second_term
            second_term += first_term
            final_key.append([first_term,second_term])

        return final_key


    def extract_key(self, encrypted_string, extraction_table) -> tuple:
        '''
            Extracts key from encrypted string.

            Returns:
                (str): decrypted key
                (str): new encrypted string
        '''
        decrypted_key = []
        offset = 0

        for start, end in extraction_table:
            decrypted_key.append(encrypted_string[start - offset:end - offset])
            encrypted_string = (
                encrypted_string[:start - offset] + encrypted_string[end - offset:]
            )
            offset += end - start

        return "".join(decrypted_key), encrypted_string


    def generate_encryption_key(self, salt, secret) -> bytes:
        '''
            Generates the original AES encryption key from the salt + secret passsed.

            Returns:
                (bytes): encryption key for use in decrypting data
        '''
        key = self.calculate_md5(secret + salt)
        current_key = key
        while len(current_key) < 48:
            key = self.calculate_md5(key + secret + salt)
            current_key += key
        return current_key


    def decrypt_aes_data(self, decryption_key, data) -> str:
        '''
            Uses decryption key to decrypt reformatted data.

            Returns:
                (str): decrypted data bytes decoded as utf-8
        '''
        cipher_data = self.decode_base64_array(data)
        encrypted = cipher_data[16:]
        AES_CBC = AES.new(
            decryption_key[:32], AES.MODE_CBC, iv=decryption_key[32:]
        )
        decrypted_data = unpad(
            AES_CBC.decrypt(encrypted), AES.block_size
        )
        return decrypted_data.decode("utf-8")


    def get_cdn(self, encrypted, player) -> dict:
        '''
            Takes encrypted data, uses regex to extract rabbitstreams e4 player key, uses that key to decrypt the aforementioned data.

            Returns:
                (dict): decrypted string loaded as json
        '''
        time_start = time.time()
        e4_player = self.get_player_js(player)
        array_key = self.get_extraction_key(e4_player)
        final_key = self.get_final_key(array_key)
        time_end = time.time()

        print(f"Found key in {round(time_end - time_start, ndigits=4)} seconds: {final_key}")

        key, new_string = self.extract_key(encrypted, final_key)
        decryption_key = self.generate_encryption_key(
            self.decode_base64_array(new_string)[8:16], key.encode("utf-8")
        )
        main_decryption = self.decrypt_aes_data(decryption_key, new_string)
        return json.loads(main_decryption)
    
if __name__ == "__main__":
    data = ""
    player_type = ""

    print(Resolver().get_cdn(data, player_type))
