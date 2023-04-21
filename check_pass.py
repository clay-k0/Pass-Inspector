"""
Author: Clayton King
Date: Fri 21 Apr 2023 10:05:16
Description: This script checks if a password has been leaked in a database.
"""

import requests
import hashlib
import sys


def request_api_data(query_char):
    url = f'https://api.pwnedpasswords.com/range/{query_char}'
    response = requests.get(url)
    if response.status_code != 200:
        raise RuntimeError(f"Error fetching {response.status_code} from the API."
                           f"Check the API and try again.")
    return response


def get_password_leak_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    return next((count for hash, count in hashes if hash == hash_to_check), 0)


def check_pwned_api(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first_five_hashed, tail = sha1password[:5], sha1password[5:]
    response2 = request_api_data(first_five_hashed)
    return get_password_leak_count(response2, tail)


def main(args):
    print('Password Checker:\n')
    for password in args:
        if count := check_pwned_api(password):
            print(f'{password} was found {count} times... consider changing it.')
        else:
            print(f'All good, {password} was not found!')
    print('\nDone!')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
