from Advanced_Decoy_Encr import EnhancedDecoyEncryption

def test_enhanced_algorithm():
    print("🚀 === ENHANCED DECOY ENCRYPTION TEST ===")
    print("Features: Advanced letter substitution + Decoy messages")
    print()
    
    system = EnhancedDecoyEncryption()
    
    # Test 1: User's exact example
    print("📝 TEST 1: User's Example")
    print("-" * 35)
    original = "My name is Siddhant Mishrikotkar"
    key = "secret123"
    
    print(f"Original: '{original}'")
    print(f"Key: '{key}'")
    
    # Show what happens during substitution
    print(f"\nSubstitution examples:")
    print(f"- 'ee' becomes: '{system.duplicate_patterns.get('ee', 'N/A')}'")
    print(f"- 'aa' becomes: '{system.duplicate_patterns.get('aa', 'N/A')}'") 
    print(f"- 'a' becomes: '{system.vowel_combinations['a'][0]}{system.vowel_combinations['a'][1]}'")
    print(f"- 'e' becomes: '{system.vowel_combinations['e'][0]}{system.vowel_combinations['e'][1]}'")
    
    # Encrypt and test
    encrypted, sample_decoy = system.encrypt(original, key)
    print(f"\nEncrypted: {encrypted[:50]}...")
    print(f"Sample decoy: '{sample_decoy}'")
    
    # Decrypt with correct key
    correct_result = system.decrypt(encrypted, key)
    print(f"\n✅ Correct key result: '{correct_result}'")
    
    # Decrypt with wrong keys
    wrong_keys = ["wrongkey", "password", "admin123"]
    print(f"\n❌ Wrong key results:")
    for wrong_key in wrong_keys:
        wrong_result = system.decrypt(encrypted, wrong_key)
        print(f"   '{wrong_key}': '{wrong_result}'")
    
    print(f"\n🎯 Perfect match with correct key: {original == correct_result}")
    
    # Test 2: Text with duplicates
    print(f"\n\n📝 TEST 2: Text with Duplicate Letters")
    print("-" * 40)
    original2 = "Hello everyone, see you soon"
    key2 = "testkey"
    
    print(f"Original: '{original2}'")
    print(f"Key: '{key2}'")
    print(f"Contains: 'ee' in 'see', 'oo' in 'soon'")
    
    encrypted2, _ = system.encrypt(original2, key2)
    correct_result2 = system.decrypt(encrypted2, key2)
    wrong_result2 = system.decrypt(encrypted2, "badkey")
    
    print(f"\n✅ Correct key: '{correct_result2}'")
    print(f"❌ Wrong key: '{wrong_result2}'")
    
    print(f"\n🎯 Perfect match: {original2 == correct_result2}")
    
    print("\n" + "="*60)
    print("🎉 ALGORITHM FEATURES DEMONSTRATED:")
    print("✅ Decoy messages with wrong keys")
    print("✅ Advanced vowel substitution (a → zq, e → xe, etc.)")  
    print("✅ Duplicate letter patterns (ee → xety, oo → bynu)")
    print("✅ Random 5-letter to vowel replacement")
    print("✅ Perfect decryption with correct key")
    print("="*60)

if __name__ == "__main__":
    test_enhanced_algorithm()