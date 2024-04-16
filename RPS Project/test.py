def decrypt_message(file_path):
    # Read in the file
    with open(file_path, "r") as file:
        lines = file.readlines()
    # Create a dictionary to store the contents as word:number pairs
    word_dict = {}
    for line in lines:
        number, word = line.strip().split()
        word_dict[int(number)] = word
        # Build the decrypted message based on the established pyramid structure

    i = 1
    step = 1
    message_words = []
    while i < len(word_dict) + 1:
        message_words.append(word_dict[i])
        step = step + 1
        i = i + step

    # Join the words to form the decrypted message
    decrypted_message = " ".join(message_words)

    return decrypted_message


# Example of it's usage:
file_path = "coding_qual_input.txt"
result = decrypt_message(file_path)
print(result)
