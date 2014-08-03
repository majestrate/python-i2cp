

if __name__ == '__main__':
    from client import Connection
    import logging
    logging.basicConfig(level=logging.DEBUG)
    c = Connection()
    c.open()
    c.start_session()
    c.close()
    
