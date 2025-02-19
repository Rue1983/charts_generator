from functools import wraps
import errno
import os
import signal
from threading import Thread
import functools
import threadpool
import time


class TimeoutError(Exception):
    pass


def timeout(seconds_before_timeout):
    def deco(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            res = [TimeoutError('function [%s] timeout [%s seconds] exceeded!' % (func.__name__, seconds_before_timeout))]
            def newFunc():
                try:
                    res[0] = func(*args, **kwargs)
                except Exception as e:
                    res[0] = e
            t = Thread(target=newFunc)
            t.daemon = True
            # pool_size = 100
            # pool = threadpool.ThreadPool(pool_size)
            try:
                # requests = threadpool.makeRequests(newFunc)
                # [pool.putRequest(req) for req in requests]
                t.start()
                t.join(seconds_before_timeout)
            except Exception as e:
                print('error starting thread')
                raise e
            ret = res[0]
            if isinstance(ret, BaseException):
                raise ret
            return ret
        return wrapper
    return deco


def timeit(method):
    def timed(*args, **kw):
        ts = time.time()
        result = method(*args, **kw)
        te = time.time()
        if 'log_time' in kw:
            name = kw.get('log_name', method.__name__.upper())
            kw['log_time'][name] = int((te - ts) * 1000)
        else:
            print('%r  %2.2f ms' % (method.__name__, (te - ts) * 1000))
        return result
    return timed


@timeit
def sayhello(str):
    print("Hello ",str)
    time.sleep(12)
    print("Hello ", str)

