import threading
import asyncio
import time



def t():
    print('Threading %s start..' %'A')
    for i in range(20):
        time.sleep(0.3)
        
        print('Thread %s is running..' %'A')
        
async def f1(name):
    if name == 'A':
        print('A thread will be start..')
        tt = threading.Thread(target=t, name='A-thread')
        tt.start()
        tt.join()
    while True:
        print('%s is running..' %name)
        time.sleep(2)
        print('%s is abount to pending..' %name)
        await asyncio.sleep(2)

tasks = [f1('A'), f1('B')]
loop = asyncio.get_event_loop()
loop.run_until_complete(asyncio.wait(tasks))