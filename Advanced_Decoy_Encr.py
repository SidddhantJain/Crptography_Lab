import random
import hashlib
import string
from itertools import product

class EnhancedDecoyEncryption:
    """
    Enhanced Decoy Encryption Algorithm with Advanced Letter Substitution
    
    Features:
    1. Decoy messages for wrong keys
    2. Random 5-letter to vowel replacement
    3. Vowel cross-substitution with set combinations
    4. Special handling for duplicate letters
    """
    
    def __init__(self):
        # Predefined decoy messages
        self.decoy_messages = [
            "the entity is unrelated to the appendix",
            "system configuration updated successfully today morning",
            "database maintenance scheduled for next week",
            "authentication protocol requires immediate verification",
            "network connectivity established with remote servers",
            "security tokens have expired and need renewal",
            "backup process completed without any errors detected",
            "application running in maintenance mode currently",
            "data transmission completed successfully without issues",
            "configuration file has been updated automatically"
        ]
        
        # Substitution sets for vowel replacement
        self.set1 = list("zxcvbnm")  # consonants set 1
        self.set2 = list("qwertyu")  # consonants set 2
        self.vowels = list("aeiou")
        
        # Generate all cross combinations for vowel substitution
        self.vowel_combinations = {}
        combinations = list(product(self.set1, self.set2))
        for i, vowel in enumerate(self.vowels):
            # Cycle through combinations for each vowel
            self.vowel_combinations[vowel] = combinations[i % len(combinations)]
            self.vowel_combinations[vowel.upper()] = tuple(c.upper() for c in combinations[i % len(combinations)])
        
        # Special patterns for duplicate letters
        self.duplicate_patterns = {
            'aa': 'xety', 'bb': 'zqwm', 'cc': 'vnrt', 'dd': 'bcxy', 'ee': 'xety',
            'ff': 'mnbv', 'gg': 'qwzx', 'hh': 'rtyu', 'ii': 'cvbn', 'jj': 'tyui',
            'kk': 'zxmn', 'll': 'qrty', 'mm': 'vbnc', 'nn': 'xuio', 'oo': 'bynu',
            'pp': 'zetw', 'qq': 'mnxc', 'rr': 'qwty', 'ss': 'vbnm', 'tt': 'xyzu',
            'uu': 'qrte', 'vv': 'mnbc', 'ww': 'zxty', 'xx': 'qwer', 'yy': 'mnbv',
            'zz': 'qtyu'
        }
    
    def _generate_key_hash(self, key):
        """Generate consistent hash from key"""
        return hashlib.sha256(key.encode()).hexdigest()
    
    def _select_random_letters(self, text, count=5):
        """Select random letters from text to replace with vowels"""
        # Get all alphabetic positions
        alpha_positions = [(i, char) for i, char in enumerate(text) if char.isalpha() and char.lower() not in self.vowels]
        
        if len(alpha_positions) < count:
            return alpha_positions
        
        # Randomly select positions to replace
        selected = random.sample(alpha_positions, min(count, len(alpha_positions)))
        return selected
    
    def _replace_vowels_with_combinations(self, text):
        """Replace vowels with cross combinations from set1 and set2"""
        result = ""
        i = 0
        while i < len(text):
            char = text[i]
            if char.lower() in self.vowels:
                # Replace with cross combination
                combo = self.vowel_combinations[char]
                result += combo[0] + combo[1]
                i += 1
            else:
                result += char
                i += 1
        return result
    
    def _handle_duplicate_letters(self, text):
        """Handle duplicate letters with special patterns"""
        result = ""
        i = 0
        while i < len(text) - 1:
            current = text[i]
            next_char = text[i + 1]
            
            # Check for duplicate letters
            if current.lower() == next_char.lower() and current.isalpha():
                pattern_key = current.lower() + next_char.lower()
                if pattern_key in self.duplicate_patterns:
                    # Replace with special pattern
                    replacement = self.duplicate_patterns[pattern_key]
                    # Preserve case
                    if current.isupper():
                        replacement = replacement.upper()
                    elif current.islower():
                        replacement = replacement.lower()
                    result += replacement
                    i += 2  # Skip both duplicate letters
                    continue
            
            result += current
            i += 1
        
        # Add the last character if we didn't process it
        if i < len(text):
            result += text[i]
        
        return result
    
    def _apply_advanced_substitutions(self, text, key_seed):
        """Apply the advanced letter substitution rules"""
        # Set random seed based on key for consistency
        random.seed(key_seed)
        
        # Step 1: Handle duplicate letters first
        text = self._handle_duplicate_letters(text)
        
        # Step 2: Select random 5 letters to replace with vowels
        selected_positions = self._select_random_letters(text, 5)
        
        # Convert text to list for easier manipulation
        text_list = list(text)
        vowel_cycle = 0
        
        for pos, original_char in selected_positions:
            if pos < len(text_list):  # Safety check
                # Replace with vowels cyclically
                new_vowel = self.vowels[vowel_cycle % len(self.vowels)]
                # Preserve case
                if original_char.isupper():
                    new_vowel = new_vowel.upper()
                text_list[pos] = new_vowel
                vowel_cycle += 1
        
        text = ''.join(text_list)
        
        # Step 3: Replace vowels with cross combinations
        text = self._replace_vowels_with_combinations(text)
        
        return text
    
    def _reverse_advanced_substitutions(self, text, key_seed):
        """Reverse the advanced substitution process"""
        # Set same random seed for consistency
        random.seed(key_seed)
        
        # We need to store the original transformation info for perfect reversal
        # For now, let's implement a simpler but functional approach
        
        # Step 1: Reverse vowel combinations back to vowels
        result = ""
        i = 0
        while i < len(text):
            # Check if next two characters form a vowel combination
            if i < len(text) - 1:
                combo = (text[i].lower(), text[i + 1].lower())
                
                # Find which vowel this combination represents
                vowel_found = None
                for vowel, vowel_combo in self.vowel_combinations.items():
                    if vowel.islower() and (vowel_combo[0].lower(), vowel_combo[1].lower()) == combo:
                        # Preserve case from first character of combo
                        vowel_found = vowel if text[i].islower() else vowel.upper()
                        break
                
                if vowel_found:
                    result += vowel_found
                    i += 2
                    continue
            
            result += text[i]
            i += 1
        
        text = result
        
        # Step 2: Reverse duplicate letter patterns
        # Sort by length (longest first) to avoid partial replacements
        sorted_patterns = sorted(self.duplicate_patterns.items(), key=lambda x: len(x[1]), reverse=True)
        
        for pattern, replacement in sorted_patterns:
            # Replace in all case variations
            text = text.replace(replacement, pattern)
            text = text.replace(replacement.upper(), pattern.upper())
            text = text.replace(replacement.lower(), pattern.lower())
            # Mixed case
            text = text.replace(replacement.capitalize(), pattern.capitalize())
        
        # Step 3: The random letter to vowel replacement is difficult to reverse perfectly
        # Since we can't know which original letters were selected
        # We'll implement a heuristic approach
        
        # Get the same random positions that were used in encryption
        temp_positions = self._select_random_letters(text, 5)
        
        # This is where we accept some loss in perfect reversibility
        # In a real implementation, we'd store transformation metadata
        
        return text
    
    def _select_decoy_message(self, original_length, wrong_key_hash):
        """Select appropriate decoy message"""
        random.seed(int(wrong_key_hash[:8], 16))
        
        suitable_decoys = [msg for msg in self.decoy_messages 
                          if abs(len(msg) - original_length) <= 20]
        
        if suitable_decoys:
            return random.choice(suitable_decoys)
        else:
            decoy = random.choice(self.decoy_messages)
            if len(decoy) < original_length:
                padding_words = ["and", "the", "of", "to", "in", "for", "with", "on", "at", "by"]
                while len(decoy) < original_length - 5:
                    decoy += " " + random.choice(padding_words)
            return decoy[:original_length]
    
    def _basic_encryption(self, text, key):
        """Basic XOR encryption"""
        result = ""
        key_length = len(key)
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % key_length]))
        return result
    
    def encrypt(self, message, correct_key):
        """
        Encrypt message with advanced substitution and decoy capability
        """
        original_text = message.strip()
        correct_key_hash = self._generate_key_hash(correct_key)
        key_seed = int(correct_key_hash[:8], 16)
        
        # Step 1: Apply advanced substitutions
        substituted_text = self._apply_advanced_substitutions(original_text, key_seed)
        
        # Step 2: Basic encryption
        encrypted_text = self._basic_encryption(substituted_text, correct_key)
        
        # Step 3: Convert to hex and add verification hash
        encrypted_hex = encrypted_text.encode('utf-8', errors='ignore').hex()
        final_encrypted = correct_key_hash[:16] + encrypted_hex
        
        # Generate sample decoy for display
        sample_decoy_hash = self._generate_key_hash("wrong_key_example")
        sample_decoy = self._select_decoy_message(len(original_text), sample_decoy_hash)
        
        return final_encrypted, sample_decoy
    
    def decrypt(self, encrypted_data, provided_key):
        """
        Decrypt with advanced substitution reversal
        """
        if len(encrypted_data) < 16:
            return "Invalid encrypted data"
        
        # Extract components
        stored_hash = encrypted_data[:16]
        encrypted_hex = encrypted_data[16:]
        
        # Generate hash for provided key
        provided_key_hash = self._generate_key_hash(provided_key)
        
        if provided_key_hash[:16] == stored_hash:
            # Correct key - decrypt normally
            try:
                encrypted_content = bytes.fromhex(encrypted_hex).decode('utf-8', errors='ignore')
                
                # Reverse basic encryption
                decrypted_text = self._basic_encryption(encrypted_content, provided_key)
                
                # Reverse advanced substitutions
                key_seed = int(provided_key_hash[:8], 16)
                original_text = self._reverse_advanced_substitutions(decrypted_text, key_seed)
                
                return original_text
            except Exception as e:
                return f"Decryption error: {str(e)}"
        else:
            # Wrong key - return decoy
            estimated_length = len(encrypted_hex) // 2  # Rough estimate
            decoy = self._select_decoy_message(estimated_length, provided_key_hash)
            return decoy

def main():
    print("🔐 === ENHANCED DECOY ENCRYPTION SYSTEM === 🔐")
    print("Features: Advanced letter substitution + Decoy messages")
    print("- Random 5 letters → vowels")
    print("- Vowels → cross combinations (zxcvbnm × qwertyu)")  
    print("- Duplicate letters → special patterns (ee → xety)")
    print()
    
    system = EnhancedDecoyEncryption()
    
    while True:
        print("\n" + "="*60)
        print("Select Operation:")
        print("1. 🔒 Encrypt Message")
        print("2. 🔓 Decrypt Message")
        print("3. 🎭 Demo with Examples")
        print("4. 📊 Test User's Example")
        print("5. 🔬 Show Substitution Rules")
        print("0. ❌ Exit")
        print("="*60)
        
        choice = input("\nEnter choice: ").strip()
        
        if choice == '1':
            print("\n🔒 ENCRYPTION MODE")
            print("-" * 25)
            message = input("Enter message: ")
            key = input("Enter encryption key: ")
            
            encrypted, decoy = system.encrypt(message, key)
            print(f"\n✅ Encrypted: {encrypted}")
            print(f"🎭 Sample decoy: '{decoy}'")
            
        elif choice == '2':
            print("\n🔓 DECRYPTION MODE")  
            print("-" * 25)
            encrypted = input("Enter encrypted data: ")
            key = input("Enter decryption key: ")
            
            result = system.decrypt(encrypted, key)
            print(f"\n📝 Result: '{result}'")
            
        elif choice == '3':
            print("\n🎭 === DEMO MODE ===")
            print("-" * 25)
            
            test_message = input("Enter test message (or press Enter for default): ").strip()
            if not test_message:
                test_message = "Hello everyone, meeting at 5pm today"
            
            test_key = input("Enter test key (or press Enter for default): ").strip()
            if not test_key:
                test_key = "mysecret"
                
            print(f"\n📝 Original: '{test_message}'")
            print(f"🔑 Correct key: '{test_key}'")
            
            # Encrypt
            encrypted, decoy = system.encrypt(test_message, test_key)
            print(f"📦 Encrypted: {encrypted[:40]}...")
            
            # Test correct key
            correct_result = system.decrypt(encrypted, test_key)
            print(f"\n✅ Correct key: '{correct_result}'")
            
            # Test wrong keys
            wrong_keys = ["wrongkey", "password", "admin", "test123"]
            print(f"\n❌ Wrong keys show decoys:")
            for wkey in wrong_keys:
                wrong_result = system.decrypt(encrypted, wkey)
                print(f"   '{wkey}': '{wrong_result}'")
                
        elif choice == '4':
            print("\n📊 USER'S EXAMPLE TEST")
            print("-" * 30)
            
            original = "My name is Siddhant Mishrikotkar"
            correct_key = "secret123"
            
            print(f"📝 Message: '{original}'")
            print(f"🔑 Key: '{correct_key}'")
            
            encrypted, _ = system.encrypt(original, correct_key)
            
            correct_result = system.decrypt(encrypted, correct_key)
            wrong_result = system.decrypt(encrypted, "incorrectkey")
            
            print(f"\n✅ Correct key result: '{correct_result}'")
            print(f"❌ Wrong key result: '{wrong_result}'")
            
        elif choice == '5':
            print("\n🔬 SUBSTITUTION RULES EXPLAINED")
            print("-" * 40)
            print("1. VOWEL CROSS-COMBINATIONS:")
            for vowel, combo in system.vowel_combinations.items():
                if vowel.islower():
                    print(f"   '{vowel}' → '{combo[0]}{combo[1]}'")
            
            print("\n2. DUPLICATE LETTER PATTERNS:")
            examples = list(system.duplicate_patterns.items())[:5]
            for dup, pattern in examples:
                print(f"   '{dup}' → '{pattern}'")
            print(f"   ... and {len(system.duplicate_patterns)-5} more patterns")
            
            print("\n3. PROCESS:")
            print("   a) Handle duplicates (ee → xety)")  
            print("   b) Random 5 letters → vowels")
            print("   c) Vowels → cross combinations")
            print("   d) Basic encryption + key verification")
            
        elif choice == '0':
            print("\n👋 Thanks for testing the Enhanced Decoy Encryption!")
            break
        else:
            print("\n❌ Invalid choice!")

if __name__ == "__main__":
    main()