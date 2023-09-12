import requests
import hashlib
import sys

def request_api_data(query_char):
    """
    Requests API data based on a query character.

    Parameters:
        query_char (str): The query character used to construct the API URL.

    Returns:
        requests.Response: The response object containing the API data.

    Raises:
        RuntimeError: If the API request fails with a non-200 status code.

    """
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f'Error fetching: {response.status_code}, check the api and try again')
    return response

def get_password_leak_count(hashes, hash_to_check):
    """
    Returns the count of password leaks for a given hash.

    Parameters:
    - hashes (str): A string containing the hashes and their counts in the format "hash:count".
    - hash_to_check (str): The hash to search for in the list of hashes.

    Returns:
    - int: The count of password leaks for the given hash. Returns 0 if the hash is not found.
    """
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0

def pwned_api_check(password):
    """
    Check if a password has been pwned by querying an API.

    Args:
        password (str): The password to be checked.

    Returns:
        int: The number of times the password has been found in data breaches.
    """
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leak_count(response, tail)
    
    
def main(args):
    """
    Iterates through a list of passwords and checks if each password has been compromised using the pwned_api_check function. Prints a message indicating whether each password was found in a database of compromised passwords or not. Returns a string indicating that the function has completed.

    Parameters:
    - args (list): A list of passwords to check.

    Returns:
    - str: A message indicating that the function has completed.
    """
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
