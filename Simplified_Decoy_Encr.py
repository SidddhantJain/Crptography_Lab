import random
import hashlib
from itertools import product

class SimplifiedDecoyEncryption:
    """
    Simplified Decoy Encryption with Core Features
    - Decoy messages for wrong keys  
    - Vowel cross-substitution with sets
    - Duplicate letter special patterns
    - Better reversibility
    """
    
    def __init__(self):
        self.decoy_messages = [
            "the entity is unrelated to the appendix",
            "system configuration updated successfully today morning", 
            "database maintenance scheduled for next week period",
            "authentication protocol requires immediate verification now",
            "network connectivity established with remote servers today",
            "security tokens have expired and need renewal soon",
            "backup process completed without any errors detected here",
            "application running in maintenance mode currently active",
            "data transmission completed successfully without issues found",
            "configuration file has been updated automatically by system"
        ]
        
        # Substitution sets
        self.set1 = "zxcvbnm"
        self.set2 = "qwertyu"
        self.vowels = "aeiou"
        
        # Create vowel to combination mapping
        self.vowel_map = {
            'a': 'zq', 'e': 'xw', 'i': 'ce', 'o': 'vr', 'u': 'bt'
        }
        
        # Reverse mapping
        self.reverse_vowel_map = {v: k for k, v in self.vowel_map.items()}
        
        # Duplicate patterns  
        self.duplicate_map = {
            'aa': 'xety', 'bb': 'zqwm', 'cc': 'vnrt', 'dd': 'bcxy', 
            'ee': 'xety', 'ff': 'mnbv', 'gg': 'qwzx', 'll': 'qrty',
            'mm': 'vbnc', 'nn': 'xuio', 'oo': 'bynu', 'pp': 'zetw',
            'rr': 'qwty', 'ss': 'vbnm', 'tt': 'xyzu'
        }
        
        # Reverse duplicate mapping
        self.reverse_duplicate_map = {v: k for k, v in self.duplicate_map.items()}
    
    def _key_hash(self, key):
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _select_decoy(self, length, wrong_key_hash):
        random.seed(int(wrong_key_hash[:8], 16))
        suitable = [msg for msg in self.decoy_messages if abs(len(msg) - length) <= 10]
        if suitable:
            return random.choice(suitable)
        return self.decoy_messages[0][:length]
    
    def _apply_substitutions(self, text):
        """Apply vowel and duplicate substitutions"""
        result = ""
        i = 0
        
        while i < len(text):
            # Check for duplicate letters
            if i < len(text) - 1 and text[i].lower() == text[i + 1].lower():
                dup_key = text[i].lower() + text[i + 1].lower()
                if dup_key in self.duplicate_map:
                    replacement = self.duplicate_map[dup_key]
                    # Preserve case
                    if text[i].isupper():
                        replacement = replacement.upper()
                    result += replacement
                    i += 2
                    continue
            
            # Check for vowels
            if text[i].lower() in self.vowel_map:
                replacement = self.vowel_map[text[i].lower()]
                # Preserve case
                if text[i].isupper():
                    replacement = replacement.upper()
                result += replacement
                i += 1
                continue
                
            # Regular character
            result += text[i]
            i += 1
            
        return result
    
    def _reverse_substitutions(self, text):
        """Reverse the substitutions"""
        # First reverse duplicates (longer patterns first)
        for pattern, original in self.reverse_duplicate_map.items():
            text = text.replace(pattern.upper(), original.upper())
            text = text.replace(pattern.lower(), original.lower())
            text = text.replace(pattern, original)
        
        # Then reverse vowel combinations
        result = ""
        i = 0
        while i < len(text) - 1:
            two_char = text[i:i+2].lower()
            if two_char in self.reverse_vowel_map:
                # Found vowel combination
                vowel = self.reverse_vowel_map[two_char]
                if text[i].isupper():
                    vowel = vowel.upper()
                result += vowel
                i += 2
            else:
                result += text[i]
                i += 1
        
        # Add remaining characters
        if i < len(text):
            result += text[i]
            
        return result
    
    def _xor_encrypt(self, text, key):
        """Simple XOR encryption"""
        result = ""
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
    
    def encrypt(self, message, key):
        """Encrypt with substitutions and decoy capability"""
        # Apply substitutions
        substituted = self._apply_substitutions(message)
        
        # XOR encrypt
        encrypted = self._xor_encrypt(substituted, key)
        
        # Create final format with key verification
        key_hash = self._key_hash(key)
        final = key_hash[:16] + encrypted.encode('utf-8', errors='ignore').hex()
        
        # Sample decoy
        sample_decoy = self._select_decoy(len(message), self._key_hash("wrong"))
        
        return final, sample_decoy
    
    def decrypt(self, encrypted_data, key):
        """Decrypt with substitution reversal"""
        if len(encrypted_data) < 16:
            return "Invalid data"
        
        stored_hash = encrypted_data[:16]
        encrypted_hex = encrypted_data[16:]
        
        provided_hash = self._key_hash(key)
        
        if provided_hash[:16] == stored_hash:
            # Correct key
            try:
                encrypted_bytes = bytes.fromhex(encrypted_hex)
                encrypted_text = encrypted_bytes.decode('utf-8', errors='ignore')
                
                # XOR decrypt
                decrypted = self._xor_encrypt(encrypted_text, key)
                
                # Reverse substitutions
                original = self._reverse_substitutions(decrypted)
                
                return original
            except Exception:
                return "Decryption failed"
        else:
            # Wrong key - return decoy
            decoy = self._select_decoy(len(encrypted_hex) // 2, provided_hash)
            return decoy

def test_simplified():
    print("🔐 === SIMPLIFIED DECOY ENCRYPTION TEST ===")
    print()
    
    system = SimplifiedDecoyEncryption()
    
    # Show mappings
    print("📋 SUBSTITUTION RULES:")
    print(f"Vowels: {system.vowel_map}")
    print(f"Duplicates: {dict(list(system.duplicate_map.items())[:5])}...")
    print()
    
    # Test user's example
    original = "My name is Siddhant Mishrikotkar"
    key = "secret123"
    
    print(f"📝 Original: '{original}'")
    print(f"🔑 Key: '{key}'")
    
    # Show what substitutions would look like
    substituted = system._apply_substitutions(original)
    print(f"🔄 After substitutions: '{substituted}'")
    
    # Full encrypt/decrypt test
    encrypted, decoy = system.encrypt(original, key)
    print(f"📦 Encrypted: {encrypted[:50]}...")
    print(f"🎭 Sample decoy: '{decoy}'")
    
    # Test decryption
    correct_result = system.decrypt(encrypted, key)
    wrong_result = system.decrypt(encrypted, "wrongkey")
    
    print(f"\n✅ Correct key: '{correct_result}'")
    print(f"❌ Wrong key: '{wrong_result}'")
    print(f"🎯 Perfect match: {original == correct_result}")
    
    # Test with duplicates
    print(f"\n📝 TEST WITH DUPLICATES:")
    test2 = "Hello everyone"  # has 'll' and no vowels at end to test
    encrypted2, _ = system.encrypt(test2, "testkey")
    result2 = system.decrypt(encrypted2, "testkey")
    print(f"Original: '{test2}'")
    print(f"Result: '{result2}'")  
    print(f"Match: {test2 == result2}")

if __name__ == "__main__":
    test_simplified()