from redis import Redis
from login_session import LoginSession
client = Redis(decode_responses=True)
session = LoginSession(client, 'xy')
token = session.create()
print(token)
