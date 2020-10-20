#!/usr/bin/env python3
"""
Dirwatcher - A long-running program
"""

__author__ = "Leann James with help from Pete Mayor and Mike Boring"

import argparse
import sys
import signal
import time
import os
import logging
import datetime

exit_flag = False

start_time = ""

current_directory_dict = {}


def start_watch_directory(watch_directory, magic_text, ext, polling_interval):
    '''
    Watch a directory for new files being added,
    deleted, and scan for magic word.
    '''
    if not os.path.isdir(f'{watch_directory}'):
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.ERROR)
        logger.error(f'Directory or file not found: \
                    {os.getcwd()}/{watch_directory}')
    else:
        detect_deleted_files(watch_directory)
        detect_added_files(watch_directory, ext, magic_text)
        scan_full_directory(watch_directory, ext, magic_text)


def scan_single_file(watch_directory, file_name, magic_text):
    '''
    Scan a file for the specified magic word.
    '''
    with open(f'{watch_directory}/{file_name}') as f:
        for i, line in enumerate(f):
            if magic_text in line.lower():
                logger = logging.getLogger(__name__)
                logger.setLevel(logging.INFO)
                logger.info(f'Magic word found in {file_name} on line {i+1}')
                global current_directory_dict
                current_directory_dict[file_name] = i+1
            else:
                continue


def scan_full_directory(watch_directory, ext, magic_text):
    '''
    Scan a full directory for the specified magic word.
    '''
    global current_directory_dict
    if os.path.isdir(f'{watch_directory}'):
        new_directory_list = os.listdir(watch_directory)
        if not len(new_directory_list) == 0:
            for single_file in new_directory_list:
                if single_file.endswith(ext):
                    with open(f'{watch_directory}/{single_file}') as f:
                        for i, line in enumerate(f):
                            if magic_text in line.lower():
                                if single_file in current_directory_dict:
                                    if current_directory_dict[single_file]\
                                            < i+1:
                                        logger = logging.getLogger(__name__)
                                        logger.setLevel(logging.INFO)
                                        logger.info(f'Magic word found in\
                                            {single_file} on line {i+1}')
                                        current_directory_dict[single_file]\
                                            = i+1
                                else:
                                    current_directory_dict[single_file] = i+1
                                    pass


def detect_added_files(watch_directory, ext, magic_text):
    '''
    Detect when a file is added to the directory being watched.
    '''
    global current_directory_dict
    new_directory_list = os.listdir(watch_directory)
    if len(new_directory_list) == 0:
        return
    else:
        for f in new_directory_list:
            if f.endswith(ext) and f not in current_directory_dict:
                logger = logging.getLogger(__name__)
                logger.setLevel(logging.INFO)
                logger.info(f'New file detected: {f}')
                current_directory_dict[f] = 0
                scan_single_file(watch_directory, f, magic_text)
            else:
                continue


def detect_deleted_files(watch_directory):
    '''
    Detect when a log file is deleted from the directory being watched.
    '''
    global current_directory_dict
    new_directory_list = os.listdir(watch_directory)
    if len(new_directory_list) == 0:
        return
    else:
        for dict_entry in current_directory_dict:
            if dict_entry not in new_directory_list:
                del current_directory_dict[dict_entry]
                logger = logging.getLogger(__name__)
                logger.setLevel(logging.INFO)
                logger.info('Files were deleted.')


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('path', help='specifies the directory to watch')
    parser.add_argument('magic', help='string to watch for')
    parser.add_argument('-e', '--ext',
                        help='text file extention to watch')
    parser.add_argument('-i', '--interval', type=int,
                        default=1, help='the polling interval')
    return parser


def signal_handler(signum, frame):
    # Your code here
    """
    This is a handler for SIGTERM and SIGINT.
    Other signals can be mapped here as well (SIGHUP?)
    Basically, it just sets a global flag, and main()
    will exit its loop if the signal is trapped.
    :param sig_num: The integer signal number that was
    trapped from the OS.
    :param frame: Not used
    :return None
    """
    global exit_flag
    global start_time
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.WARNING)
    # log the associated signal name
    logger.warning(
        f'Received OS process signal,{signal.Signals(signum).name}'
        )
    logger2 = logging.getLogger(__name__)
    logger2.setLevel(logging.INFO)
    logger2.info(
        f'''
        ----------------------------------------
        \tStopped {sys.argv[0]}
        \tUptime was: {datetime.datetime.now() - start_time}
        '''
        )
    exit_flag = True


def main(args):
    # Your code here
    global start_time
    start_time = datetime.datetime.now()
    logger = logging.getLogger(__name__)
    logging.basicConfig(
        format='%(asctime)s.%(msecs)03d %(name)-12s %(levelname)-8s\
        [%(threadName)-12s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        )
    logger.setLevel(logging.INFO)
    logger.info(
        f'''
        ------------------------------------
        \tRunning {sys.argv[0]}
        \tStarted on: {start_time}
        ------------------------------------
        '''
        )
    parser = create_parser()
    parsed_args = parser.parse_args(args)
    ext = parsed_args.ext
    polling_interval = parsed_args.interval
    magic_text = parsed_args.magic.lower()
    watch_directory = parsed_args.path

    global current_directory_dict
    if not os.path.isdir(f'{watch_directory}'):
        pass
    else:
        current_directory_list = os.listdir(watch_directory)
        if len(current_directory_list) != 0:
            for f in current_directory_list:
                if f.endswith(ext) and f not in current_directory_dict:
                    current_directory_dict[f] = 0
                    logger = logging.getLogger(__name__)
                    logger.setLevel(logging.INFO)
                    logger.info(f'New file detected: {f}')
                    scan_single_file(watch_directory, f, magic_text)
    # Hook into these two signals from the OS
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # Now my signal_handler will get called if OS sends
    # either of these to my process.
    while not exit_flag:
        try:
            # call my directory watching function
            start_watch_directory(
                watch_directory, magic_text, ext, polling_interval
                )
        except ValueError:
            logger = logging.getLogger(__name__)
            logger.error('Value error received and logged.')
        except TypeError as e:
            logger = logging.getLogger(__name__)
            logger.error(f'Type {e} received and logged.')
        except RuntimeError:
            logger = logging.getLogger(__name__)
            logger.error('Run time error received and logged.')
        except Exception as e:
            # This is an UNHANDLED exception
            # Log an ERROR level message here
            logger = logging.getLogger(__name__)
            logger.error(f'Error {e} received and logged.')
            raise
        # put a sleep inside my while loop so I don't peg the cpu usage at 100%
        time.sleep(polling_interval)

    # final exit point happens here
    # Log a message that we are shutting down
    # Include the overall uptime since program start
    # search_for_magic('test.txt', 0, ns.finder)


if __name__ == '__main__':
    main(sys.argv[1:])
