import asyncio

async def func1_wait():
    print('start..')
    await asyncio.sleep(3)
    print('complete..')


async def func2():
    print('func2 start..')
    loop = asyncio.get_event_loop()
    loop.run_until_complete(asyncio.ensure_future(func1_wait()))
    print('func2 finished..')

if __name__ == '__main__':
    
    loop = asyncio.get_event_loop()
    tasks = [func2(), func2()]
    loop.run_until_complete(asyncio.wait(tasks))