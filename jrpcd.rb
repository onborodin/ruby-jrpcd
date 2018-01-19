#!@ruby@

require 'socket'
require 'openssl'
require 'time'
require 'base64'
require 'json'
require 'pp'

class HTTPServer < TCPServer

    def initialize(*args)
        @route = Hash.new
        @config = Hash.new
        @config['pidfile'] = "/dev/null"
        @config['logfile'] = "/dev/null"
        @config['pwfile'] = "/dev/null"
        super(*args)
    end

    def set_config(key, value)
        @config[key] = value
    end

    def get_config(key)
        @config[key]
    end

    def set_route(path, clazz, method)
        @route[path] = { 'class' => clazz, 'method' => method }
        self
    end
    def get_route(path)
        @route[path]
    end


    def auth(login, password)
        pwfile = @config['pwfile']
        unless File.readable?(pwfile)
            self.log("Error: Cannot read password file #{pwfile}")
            return false
        end
        begin
            File.open(@config['pwfile'], 'r').each do | line |
                (name, hash, gecos) = line.strip.split(/:/)
                if name == login
                    (dummy, type, salt, digest) = hash.split(/\$/)
                    if hash == password.crypt("$#{type}$#{salt}$")
                        return true
                    end
                    return false
                end
            end
        rescue Exception => e
            self.log("Error: " + e.to_s)
            return false
        end
    end

    def fork
        Dir.chdir('/')
        pid = Process.fork
        if pid
            exit
        end
        $stdout.reopen("/dev/null", "w")
        $stderr.reopen("/dev/null", "w")
    end

    def writepid
        pid = Process.pid
        begin
            f = File.open(@config['pidfile'], 'w+')
            self.log("Wrote pid " + pid.to_s)
            f.write(pid)
            f.close
        rescue => e
            self.log("Error: " + e.to_s)
            exit
        end
        self.log("Wrote pid " + pid.to_s)
    end

    def log(message)
        ts = Time.now.strftime("%Y-%m-%d %H:%M:%S")
        rec = ts + ' ' + message + "\n"
        $stderr.puts rec
        f = File.open(@config['logfile'], 'a+')
        f.write(rec)
        f.close
    end

    def rpc(json_req)
        req = Hash.new
        begin
            req = JSON.parse(json_req);
        rescue Exception => e
            self.log("Error: " + e.to_s)
            res = {
                'jsonrpc' => '2.0',
                'error' => {
                    'code' => -32700,
                    'message' => 'Parse error',
                    'data' => e.message
                }
            }
            return res.to_json
        end
        out = "Hi!"
        res = {
            'jsonrpc' => '2.0',
            'result' => out,
            'id' => req['id']
        }
        res.to_json
    end

    def message_errlength
        res = "Length required"
        message = String.new
        message += "HTTP/1.1 411 Length required\r\n"
        message += "Date: " + Time.now.httpdate + "\r\n"
        message += "Server: HTTPServer 0.01\r\n"
        message += "Content-Type: text/plain\r\n"
        message += "Content-Length: " + res.size.to_s + "\r\n"
        message += "\r\n"
        message += res
        message
    end

    def message_errauth
        res = "Unauthorized"
        message = String.new
        message += "HTTP/1.1 401 Unauthorized\r\n"
        message += "Date: " + Time.now.httpdate + "\r\n"
        message += "Server: HTTPServer 0.01\r\n"
        message += "Content-Type: text/plain\r\n"
        message += "Content-Length: " + res.size.to_s + "\r\n"
        message += "\r\n"
        message += res
        message
    end

    def run
        self.log("Start application")

        begin 
            sslContext = OpenSSL::SSL::SSLContext.new
            sslContext.cert = OpenSSL::X509::Certificate.new(File.read(@config['crtfile']))
            sslContext.key = OpenSSL::PKey::RSA.new(File.read(@config['keyfile']))
            sslServer = OpenSSL::SSL::SSLServer.new(self, sslContext)
            sslServer.start_immediately = true
        rescue => e
            self.log("Error: " + e.to_s)
            exit
        end

        loop do
            begin 
                Thread.start(sslServer.accept) do |session|
                    request = Hash.new
                    params = Hash.new

                    until (line = session.gets) && (line.inspect.eql?('"\r\n"'))
                        line.strip!
                        if line.match(/^POST/)
                            (method, uri, proto) = line.split(/ /)
                            request['method'] = method
                            request['uri'] = uri
                            request['proto'] = proto
                            (path, params) = uri.split(/\?/)
                            request['path'] = path
                        elsif line.match(/:/)
                            (key, value) = line.split(/:/)
                            request[key.strip.downcase] = value.strip
                        end
                    end

                    (sock_domain, remote_port, remote_hostname, remote_ip) = session.peeraddr

                    message = String.new
                    message += remote_ip
                    message += ' ' + request['method']
                    message += ' ' + request['host']
                    message += ' ' + request['path']

                    self.log(message)

                    unless request['content-length']
                        session.puts(self.errlength)
                        session.close
                        next
                    end

                    if request['method'].match(/POST/) && request['content-length']
                        size = request['content-length'].to_i
                        body = session.read(size)
                    end

                    aut = false
                    if request['authorization']
                        (basic, pair) = request['authorization'].split(/ /)
                        (login, password) = Base64.decode64(pair).split(/:/)
                        a = self.auth(login, password)
                    end

                    unless a == true
                        session.puts self.errauth
                        session.close
                        next
                    end

                    res = self.rpc(body)

                    session.puts "HTTP/1.1 200 OK\r\n"
                    session.puts "Date: " + Time.now.httpdate + "\r\n"
                    session.puts "Server: HTTPServer 0.01\r\n"
                    session.puts "Content-Type: application/json\r\n"
                    session.puts "Content-Length: " + res.size.to_s + "\r\n"
                    session.puts "\r\n"
                    session.puts res

                    session.close
                end
            rescue => e
                self.log("Error: " + e.to_s)
                next
            end
        end
    end

    def shutdown(reason)
        self.log("Shutdown application: " + reason.to_s)
        pidfile = self.get_config('pidfile')
        if File.exist?(pidfile)
            File.delete(self.get_config('pidfile'))
        end
        exit
    end
end

require 'optparse'

params = ARGV.getopts("hf")

if params['h'] == true
    puts "Usage:\n"
    puts " -f No fork\n"
    puts " -h Show this help\n"
    puts "\n"
    exit
end

if params['f'] == true
    nofork = true
end

server = HTTPServer.new('0.0.0.0', 4431)

server.set_config('pidfile', '@app_rundir@/jrpcd.pid')
server.set_config('logfile', '@app_logdir@/jrpcd.log')
server.set_config('pwfile', '@app_confdir@/jrpcd.pw')
server.set_config('crtfile', '@app_confdir@/jrpcd.crt')
server.set_config('keyfile', '@app_confdir@/jrpcd.key')


Signal.trap('INT') do
    server.shutdown('Handle INT signal')
end

Signal.trap('TERM') do
    server.shutdown('Handle TERM signal')
end

#server.set_route('/rpc', 'RPC', 'run')
unless nofork == true
    server.fork
end
server.writepid
server.run

#EOF
