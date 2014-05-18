#!/usr/bin/env python
#-*- coding: utf-8 -*-
#__author__ = 'Ario'

from optparse import OptionParser
import threadpool
import traceback
import logging
import urllib2
import random
import socket
import socks
import time
import sys

logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
                #datefmt='%a, %d %b %Y %H:%M:%S'
                #filename='myapp.log',
                #filemode='w'
				)

class proxy:
    def __init__(self, type, proxy_file):
        self.type = type
        self.proxy_file = proxy_file
        self.proxy_addr_list = self.__read_dict()

    def get_one_proxy(self, proxy_addr=''):
        if proxy_addr != '':
            try:
                self.proxy_addr_list.remove(proxy_addr)
            except:
                logging.warning('proxy used up,exiting...')
                sys.exit(0)
        self.proxy_addr = random.choice(self.proxy_addr_list)
        return self.proxy_addr

    def __read_dict(self):
        lines = []
        try:
            with open(self.proxy_file, 'r') as f:
                for line in f:
                    lines.append(line.strip())
        except IOError as err:
            logging.err("File Error:" + str(err))
        return lines


class HttpProxy(proxy):
    def __init__(self, type, proxy_file):
        proxy.__init__(self, type, proxy_file)

    def set_proxy(self, proxy_addr):
        '''
		set the http proxy
		'''
        self.proxy_addr = proxy_addr
        proxy_handler = urllib2.ProxyHandler({'http': self.proxy_addr})
        opener = urllib2.build_opener(proxy_handler)
        urllib2.install_opener(opener)


class Sock5Proxy(proxy):
    def __init__(self, type, proxy_file):
        proxy.__init__(self, type, proxy_file)

    def set_proxy(self, proxy_addr):
        '''
		set the socks5 proxy
		'''
        self.proxy_addr = proxy_addr
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, proxy_addr.split(':')[0], proxy_addr.split(':')[1])
        socket.socket = socks.socksocket


def set_my_proxy(proxy_type, proxy_list):
    global proxy_addr, my_proxy
    proxy_addr = ''
    if proxy_type == 'http':
        my_proxy = HttpProxy(proxy, proxy_list)
    elif proxy_type == 'socks5':
        my_proxy = Sock5Proxy(proxy, proxy_list)
    proxy_addr = my_proxy.get_one_proxy(proxy_addr)
    my_proxy.set_proxy(proxy_addr)


def audit(host, file, proxy, threads, proxy_list):
    set_my_proxy(proxy, proxy_list)
    path_list = read_dict(file)
    url_list = [host + path for path in path_list] #todo:enhance heavy url check 
    thread_pool(url_list, threads)

def heavy_audit(host, file, proxy, threads, proxy_list):
    meta_path_list=[]
    set_my_proxy(proxy, proxy_list)
    path_list = read_dict(file)
    for path in path_list:
        meta_path=path.split('\/')
        meta_path_list.extend(meta_path)

def open_url(url):
    request = urllib2.Request(url)
    request.add_header('User-Agent', 'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)')
    result = ''
    try:
        response = urllib2.urlopen(request, timeout=10)
        code = response.getcode()
        if code == 200: #todo:enhance the code check to avoid false positive finding
            result = code
    except urllib2.URLError, e:
        result = '404'
    except socket.timeout, e:
        result = 'timeout'
        proxy_addr = my_proxy.get_one_proxy(proxy_addr)
        my_proxy.set_proxy(proxy_addr)
    except:
        logging.err('Some error/exception occurred.\n')
    finally:
        return result


def thread_pool(url_list, threads):
    pool = threadpool.ThreadPool(threads)
    reqs = threadpool.makeRequests(open_url, url_list, print_result, exc_callback)
    [pool.putRequest(req) for req in reqs]
    pool.wait()


def exc_callback(excinfo):
    errorstr = ''.join(traceback.format_exception(*excinfo))
    logging.err(errorstr)


def print_result(request, result):
    logging.info( "Testing %s ... : %s" % (request.args, result))
    if result == 200:
        logger('save', request.args)


def read_dict(file):
    lines = []
    try:
        with open(file, 'r') as f:
            for line in f:
                lines.append(line.strip())
    except IOError as err:
        logging.err("File Error:" + str(err))
    return lines


def logger(args, string='', file='log.txt'): #tod:add debug level	
    try:
        if args == 'init':
            with open(file, 'w') as f:
                f.write('Start Test.......\n')
        elif args == 'result':
            logging.info( "==============================" )
            logging.info( "show result........\n" )
            with open(file, 'r') as f:
                logging.info( f.read())
        elif args == 'save':
            with open('log.txt', 'a+') as f:
                f.write("%s ... successful\n" % string)
    except IOError as err:
        logging.err("File Open Error:" + str(err))
    return


def main():
    options = OptionParser(usage='%prog url [options]', description='Test for path brute force attack')
    options.add_option('-d', '--dict', type='string', default='php.txt', help='dictionary of path for using')
    options.add_option('-p', '--proxy', type='string', default='http', help='proxy type:http,socks5')
    options.add_option('-t', '--threads', type='int', default='1000', help='set threads')
    options.add_option('-l', '--list', type='string', default='', help='proxy list')

    opts, args = options.parse_args()
    if len(args) < 1:
        options.print_help()
        return
    logger('init')
    audit(args[0], opts.dict, opts.proxy, opts.threads, opts.list)
    logger('result')


if __name__ == '__main__':
    start = time.clock()
    main()
    elapsed = (time.clock() - start)
    print("Time used:", elapsed)