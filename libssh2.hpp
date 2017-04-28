/**
 * Copyright Ruben De Smet 2013
 * 
 * A lot of information was taken from the examples at
 * 
 */

//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Lesser General Public License as
//  published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Lesser General Public License for more details.
//  
//  You should have received a copy of the GNU Lesser General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern "C"
{
#include <libssh2.h>
#include <libssh2_sftp.h>
 
#ifdef WIN32 // WINDOZE
#include <windows.h>
#include <winsock2.h>
#else // UNIX
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif
 
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
}
    
#include <mutex>
#include <sstream>
#include <iostream>
#include <atomic>
#include <iomanip>

namespace libssh2
{
    static std::atomic_uint __libshh2_session_count;
    static std::mutex __libshh2_session_count_mutex;
    
    typedef unsigned char auth_methods_t;
    class auth_methods
    {
    public:
        static const auth_methods_t PASSWORD    = 1;
        static const auth_methods_t KEYS        = 2;
        static const auth_methods_t INTERACTIVE = 4;
    };
    
    //////////////// Exceptions ////////////////////

    class exception : std::exception
    {
    public:
        exception()
        {
            this->_what = "A generic exception has occurred.";
        }
        exception(std::string what)
        {
            this->_what = what;
        }
        const char* what()
        {
            return this->_what.c_str();
        }
    protected:
        std::string _what;
    };
    
    
    class connect_exception : public exception
    {
    public:
        connect_exception(int error_number)
        {
            // Convert error number to string
            this->_errorno = error_number;
            std::stringstream w;
            w << "Connection on socket failed with " << error_number;
            this->_what = w.str();
        }
        int get_socket_error()
        {
            return this->_errorno;
        }
    private:
        int _errorno;
    };
    
    class authentication_exception : public exception
    {
    public:
        authentication_exception()
        {
            this->_what = "Could not use the authentication method specified.";
        }
    };
    
    /////////// END EXCEPTIONS ///////////////
    
    

    class channel
    {
        friend class session;
    public:
        void request_pty()
        {
            this->request_pty("vanilla");
        }
        void request_pty(std::string term)
        {
            if( libssh2_channel_request_pty(this->_chan, term.c_str()) )
            {
                exception e("Could not request a pty.");
                throw e;
            }
        }

        void execute(const char *command) {
            int rc = libssh2_channel_exec(this->_chan, command);
            if( rc != 0 ) {
                std::stringstream s;
                s << "libssh2_channel_exec() error, code: " << rc;
                exception e(s.str());
                throw e;
            }

            do {
                char buffer[0x4000];
                rc = libssh2_channel_read(this->_chan, buffer, sizeof(buffer));
                for(int i=0; i < rc; ++i) fputc(buffer[i], stdout);
            } while(rc > 0);
        }

        ssize_t write(const char *buf, size_t buflen) {
            printf("libssh2 channel:%p\n", this->_chan);
            return libssh2_channel_write(this->_chan, buf, buflen);
        }

        ssize_t read(char *buf, size_t buflen) {
            return libssh2_channel_read(this->_chan, buf, buflen);
        }

        int eof() {
            return libssh2_channel_eof(this->_chan);
        }

        ~channel()
        {
            libssh2_channel_free(this->_chan);
        }
    private:
        channel(LIBSSH2_CHANNEL* c)
        {
            this->_chan = c;
        }
        
        LIBSSH2_CHANNEL* _chan;
    };
    
    /*
     * sftp
     */
    class sftp
    {
        friend class session;
        public:
            virtual ~sftp() {
                libssh2_sftp_shutdown(_sftp);
            }

            void get(const char *remotepath, const char *localpath) {
                LIBSSH2_SFTP_HANDLE *sftp_handle;
                sftp_handle = libssh2_sftp_open(_sftp, remotepath, LIBSSH2_FXF_READ, 0);
                if (!sftp_handle) {
                    std::stringstream s;
                    s << "Unable to open file with SFTP: " << strerror(libssh2_sftp_last_error(_sftp));
                    exception e(s.str());
                    throw e;
                }

                FILE *fp = fopen(localpath, "wb");
                if (!fp) {
                    std::stringstream s;
                    s << "Can't open local file: " << localpath;
                    exception e(s.str());
                    throw e;
                }

                do {
                    char mem[1024];
                    int rc = libssh2_sftp_read(sftp_handle, mem, sizeof(mem));

                    if (rc > 0) {
                        fwrite(mem, 1, rc, fp);
                    } else {
                        break;
                    }
                } while (1);

                fclose(fp);
                libssh2_sftp_close(sftp_handle);
            }

            void put(const char *localpath, const char *remotepath) {
                LIBSSH2_SFTP_HANDLE *sftp_handle = 
                    libssh2_sftp_open(_sftp, remotepath,
                            LIBSSH2_FXF_WRITE|LIBSSH2_FXF_CREAT|LIBSSH2_FXF_TRUNC,
                            LIBSSH2_SFTP_S_IRUSR|LIBSSH2_SFTP_S_IWUSR|
                            LIBSSH2_SFTP_S_IRGRP|LIBSSH2_SFTP_S_IROTH);
                if (!sftp_handle) {
                    std::stringstream s;
                    s << "Unable to open file with SFTP: " << remotepath;
                    exception e(s.str());
                    throw e;
                }

                FILE *fp = fopen(localpath, "rb");
                if (!fp) {
                    std::stringstream s;
                    s << "Can't open local file: " << localpath;
                    exception e(s.str());
                    throw e;
                }

                int rc;
                char mem[1024*100];
                size_t nread;
                char *ptr;
                do {
                    nread = fread(mem, 1, sizeof(mem), fp);
                    if (nread <= 0) {
                        /* end of file */ 
                        break;
                    }
                    ptr = mem;
                    do {
                        /* write data in a loop until we block */ 
                        rc = libssh2_sftp_write(sftp_handle, ptr, nread);
                        if(rc < 0)
                            break;
                        ptr += rc;
                        nread -= rc;
                    } while (nread);
                } while (rc > 0);

                fclose(fp);
                libssh2_sftp_close(sftp_handle);
            }
        private:
            sftp(LIBSSH2_SFTP *s) {
                _sftp = s;
            }

            LIBSSH2_SFTP * _sftp;
    };
    
    class fingerprint
    {
    public:
        fingerprint(LIBSSH2_SESSION* s)
        {
            this->_session = s;
            this->_md5  = libssh2_hostkey_hash(s, LIBSSH2_HOSTKEY_HASH_MD5);
            if(this->_md5 == NULL)
            {
                libssh2::exception e("Could not get MD5 signature.");
                throw e;
            }
            this->_sha1 = libssh2_hostkey_hash(s, LIBSSH2_HOSTKEY_HASH_SHA1);
            if(this->_sha1 == NULL)
            {
                libssh2::exception e("Could not get SHA1 signature.");
                throw e;
            }
        }
        const char * get_md5()
        {
            return this->_md5;
        }
        const char * get_sha1()
        {
            return this->_sha1;
        }
        std::string get_hex_md5()
        {
            if(this->_hex_md5.length() == 0)
            {
                std::string hex;
                std::stringstream s;
                s << std::hex << std::setfill('0');
                for(unsigned char i = 0; i < 16; i++)
                {
                    s << std::setw(2) << int(this->_md5[i]);
                    hex += ":" + s.str().substr(s.str().length() - 2, 2);
                    s.str("");
                }
                this->_hex_md5 = hex.substr(1); // Get rid of the first colon
            }
            return this->_hex_md5;
        }
        std::string get_hex_sha1()
        {
            if(this->_hex_sha1.length() == 0)
            {
                std::string hex;
                std::stringstream s;
                s << std::hex << std::setfill('0');
                for(unsigned char i = 0; i < 20; i++)
                {
                    s << std::setw(2) << int(this->_sha1[i]);
                    hex += ":" + s.str().substr(s.str().length() - 2, 2);
                    s.str("");
                }
                this->_hex_sha1 = hex.substr(1); // Get rid of the first colon
            }
            return this->_hex_sha1;
        }
        
    private:
        const char* _md5;
        const char* _sha1;
        
        std::string _hex_md5;
        std::string _hex_sha1;
        
        LIBSSH2_SESSION* _session;
    };

    
    /**
     * The base class of the libssh2pp library.
     * Everything starts here.
     */
    class session
    {
        friend class channel;
    public:
        
        /**
         * The default constructor.
         * It takes no arguments and makes sure that libssh2 is initialized in an 
         * atomical and thread safe way.
         */
        session()
        {
            // Initialize stupid windows systems
#ifdef WIN32
            WSADATA wsadata;
 
            WSAStartup(MAKEWORD(2,0), &wsadata);
#endif
            // Initialize libssh2 on a thread safe manner, count the session instances.
            libssh2::__libshh2_session_count_mutex.lock();
            {
                if(__libshh2_session_count == 0)
                {
                    _rc = libssh2_init(0);
                }
                this->_throw_on_error();
                __libshh2_session_count++;
            }
            libssh2::__libshh2_session_count_mutex.unlock();
            _sock = socket(AF_INET, SOCK_STREAM, 0);
            
            this->_sess = libssh2_session_init();
        }
        /** 
         * Opens the ssh session.
         * Currently, only IP addresses are supported.
         * @param      host    The host to connect to, currently only IPv4 addresses.
         * @param      port    The port where the host is listening on.
         * @throw      libssh_exception
         */
        void open(std::string host, unsigned short port)
        {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port);
            sin.sin_addr.s_addr = inet_addr(host.c_str());
            if(
                connect(_sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in))
                != 0
            )
            {
                // Socket connection error, throw
                connect_exception e(errno);
                throw e;
            }
            
            _rc = libssh2_session_handshake(this->_sess, this->_sock);
            this->_throw_on_error();
        }

        auth_methods_t get_auth_methods(std::string username)
        {    
            char* userauthlist;
            auth_methods_t types = 0;
            
            userauthlist = libssh2_userauth_list(this->_sess, username.c_str(), username.length());

            if (strstr(userauthlist, "password") != NULL) {
                types |= auth_methods::PASSWORD;
            }
            if (strstr(userauthlist, "keyboard-interactive") != NULL) {
                types |= auth_methods::INTERACTIVE;
            }
            if (strstr(userauthlist, "publickey") != NULL) {
                types |= auth_methods::KEYS;
            }
        }

        fingerprint get_host_fingerprint()
        {
            return fingerprint(this->_sess);
        }

        void auth_password(std::string username, std::string password) throw(authentication_exception)
        {
            // TODO Check the return value for the specific error.
            if(libssh2_userauth_password(this->_sess, username.c_str(), password.c_str()))
            {
                authentication_exception e;
                throw e;
            }
        }
        channel* open_channel()
        {
            LIBSSH2_CHANNEL* _chan;
            // TODO Check the return value for the specific error.
            if (!(_chan = libssh2_channel_open_session(this->_sess)))
            {
                exception e("Could not open channel");
                throw e;
            }
            channel* c = new channel(_chan);
            return c;
        }

        channel* open_tunnel(const char *remotehost, int remoteport)
        {
            LIBSSH2_CHANNEL* _chan;
            _chan = libssh2_channel_direct_tcpip(this->_sess, remotehost, remoteport);
            if (!_chan) {
                exception e("Could not open the direct-tcpip channel!\n"
                        "(Note that this can be a problem at the server!"
                        " Please review the server logs.)");
                throw e;
            }
            //libssh2_session_set_blocking(this->_sess, 0);
            printf("libssh2 channel 111:%p\n", _chan);
            channel* c = new channel(_chan);
            return c;
        }

        sftp* open_sftp()
        {
            LIBSSH2_SFTP *sftp_session;
            sftp_session = libssh2_sftp_init(this->_sess);
            if (!sftp_session) {
                exception e("Unable to init SFTP session");
                throw e;
            }
            sftp* s = new sftp(sftp_session);
            return s;
        }

        virtual ~session()
        {
            // TODO Make sure the session is shut down and channels are closed
            /* libssh2_session_disconnect, libssh2_session_free
             * 
             */
            // We lock the mutex, so there can't be an initialize while exiting.
            __libshh2_session_count_mutex.lock();
            {
                __libshh2_session_count--;
                if(__libshh2_session_count == 0)
                {
                    // Nobody is still using the ssh library, cleanup.
                    libssh2_exit();
                }
            }
            __libshh2_session_count_mutex.unlock();
#ifdef WIN32
            closesocket(_sock);
#else
            close(_sock);
#endif
        }
    private:
        int _sock;
        int _rc;
        
        LIBSSH2_SESSION * _sess;
        
        void _throw_on_error()
        {
            if(_rc != 0)
            {
                // We 've got an error
                std::stringstream s;
                s << "Sshlib2 status code: " << _rc;
                exception e(s.str());
                throw e;
            }
        }
    };

}
