from multiprocessing import Process, Value, Array



def f(n, a):
    n.value += 3.1415927
    for i in range(len(a)):
        a[i] = -a[i]

def ff(n, a):
    f(n, a)

def fff(n, a):
    ff(n, a)

if __name__ == '__main__':
    num = Value('d', 0.0)
    arr = Array('i', range(10))
    p = Process(target=ff, args=(num, arr))
    p.start()
    p.join()
    
    print(num.value)
    print(arr[:])