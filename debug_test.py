from FINAL_Complete_Decoy_System import FinalDecoyEncryption

def debug_case():
    """Debug the failing case"""
    system = FinalDecoyEncryption()
    
    message = "The meeting is at 5pm today"
    
    print(f"Original: '{message}'")
    
    # Step by step
    step1 = system._apply_duplicate_patterns(message)
    print(f"After duplicates: '{step1}'")
    
    step2 = system._apply_vowel_substitutions(step1)
    print(f"After vowels: '{step2}'")
    
    # Reverse
    rev1 = system._reverse_vowel_substitutions(step2)
    print(f"Reverse vowels: '{rev1}'")
    
    rev2 = system._reverse_duplicate_patterns(rev1)
    print(f"Final reverse: '{rev2}'")
    
    print(f"Match: {message == rev2}")

if __name__ == "__main__":
    debug_case()