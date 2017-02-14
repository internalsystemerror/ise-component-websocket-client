<?php

namespace Ise\WebSocket;

class Client extends AbstractWebSocket
{
    
    /**
     * {@inheritDoc}
     */
    public function __construct(array $options)
    {
        if (!isset($options['uri'])) {
            throw new Exception\InvalidArgumentException('Options array requires a key "uri"');
        }
        parent::__construct($options);
    }

    /**
     * Set uri
     *
     * @param string $uri
     * @return self
     */
    public function setUri($uri)
    {
        if ($this->options['uri'] !== (string) $uri) {
            $this->options['uri'] = (string) $uri;
            if ($this->isConnected()) {
                $this->disconnect();
                $this->connect();
            }
        }
        return $this;
    }

    /**
     * Get uri
     *
     * @return string
     */
    public function getUri()
    {
        return $this->options['uri'];
    }

    /**
     * {@inheritDoc}
     */
    public function connect()
    {
        // Get connection details
        $connection = $this->parseUri();
        $context    = $this->getStreamContext();

        // Create the socket
        $this->createWebSocket($connection, $context);

        // Send headers
        $securityKey = $this->generateKey();
        $headers     = $this->createConnectionHeaders($connection, $securityKey);
        $this->write($headers);

        // Get response
        $response = stream_get_line($this->socket, 1024, self::EOL . self::EOL);

        // Validate response
        if (!preg_match('/^Sec-WebSocket-Accept:\s(.*)$/mUi', $response, $matches)) {
            throw new Exception\RuntimeException(sprintf(
                'Connection to "%s" failed: Server sent invalid upgrade response.' . "\n" . '%s',
                $this->options['uri'],
                $response
            ));
        }
        $accepted = trim($matches[1]);
        $expected = base64_encode(pack('H*', sha1($securityKey . '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')));
        if ($accepted !== $expected) {
            throw new Exception\RuntimeException(sprintf(
                'Server sent a bad upgrade response. Expected: "%s", given: "%s"',
                $expected,
                $accepted
            ));
        }

        echo "\t", 'Connected...', PHP_EOL;
        // Set connected
        $this->connected = true;
    }

    /**
     * {@inheritDoc}
     */
    public function disconnect()
    {
        if (!$this->socket || !$this->connected) {
            return;
        }

        if (is_resource($this->socket) && get_resource_type($this->socket) === 'stream') {
            $this->close();
        }
        $this->socket = null;
        echo "\t", 'Disconnected...', PHP_EOL;
    }

    /**
     * Get connection details from URI
     *
     * @return array
     * @throws InvalidArgumentException
     */
    protected function parseUri()
    {
        // Parse URL
        $parsedUrl = parse_url($this->options['uri']);
        $scheme    = $parsedUrl['scheme'];
        $host      = $parsedUrl['host'];
        $port      = isset($parsedUrl['port']) ? $parsedUrl['port'] : ($scheme === 'wss' ? 443 : 80);
        $path      = isset($parsedUrl['path']) ? $parsedUrl['path'] : '/';
        $username  = isset($parsedUrl['user']) ? $parsedUrl['user'] : '';
        $password  = isset($parsedUrl['pass']) ? $parsedUrl['pass'] : '';
        $query     = isset($parsedUrl['query']) ? $parsedUrl['query'] : '';
        $fragment  = isset($parsedUrl['fragment']) ? $parsedUrl['fragment'] : '';

        // Create full path
        $fullPath = $path;
        if ($query) {
            $fullPath .= '?' . $query;
        }
        if ($fragment) {
            $fullPath .= '#' . $fragment;
        }

        // Create host URL
        if (!in_array($scheme, ['ws', 'wss'])) {
            throw new Exception\InvalidArgumentException(sprintf(
                'URI should have scheme ws or wss, "%s" given.',
                $scheme
            ));
        }
        $connectionUrl = ($scheme === 'wss' ? 'ssl' : 'tcp') . '://' . $host;

        return [
            'connectionUrl' => $connectionUrl,
            'scheme'        => $scheme,
            'host'          => $host,
            'port'          => $port,
            'username'      => $username,
            'password'      => $password,
            'fullPath'      => $fullPath,
        ];
    }

    /**
     * Get stream context
     *
     * @return resource
     * @throws InvalidArgumentException
     */
    protected function getStreamContext()
    {
        if (isset($this->options['context'])) {
            $context = $this->options['context'];
            if (!is_resource($context) || get_resource_type($context) !== 'stream-context') {
                throw new Exception\InvalidArgumentException('Stream context is not valid.');
            }
            return $context;
        }

        return stream_context_create();
    }

    /**
     * Create web socket
     *
     * @param array $connection
     * @param resource $context
     * @throws RuntimeException
     */
    protected function createWebSocket($connection, $context)
    {
        $this->socket = stream_socket_client(
            $connection['connectionUrl'] . ':' . $connection['port'],
            $errorNumber,
            $errorString,
            $this->options['timeout'],
            STREAM_CLIENT_CONNECT,
            $context
        );
        if (!$this->socket) {
            throw new Exception\RuntimeException(sprintf(
                'Could not open socket to "%s:%d": [%d] %s.',
                $connection['host'],
                $connection['port'],
                $errorNumber,
                $errorString
            ));
        }
        stream_set_timeout($this->socket, $this->options['timeout']);
    }

    /**
     * Generate security key
     *
     * @return string
     */
    protected function generateKey()
    {
        $allowedCharacters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"$&/()=[]{}0123456789';
        $lastCharacter     = strlen($allowedCharacters) - 1;
        $securityKey       = '';
        for ($i = 0; $i < 16; $i++) {
            $securityKey .= $allowedCharacters[mt_rand(0, $lastCharacter)];
        }
        return base64_encode($securityKey);
    }

    /**
     * Create header string
     *
     * @param array $connection
     * @param string $securityKey
     * @return string
     */
    protected function createConnectionHeaders($connection, $securityKey)
    {
        // Create default headers
        $headers = [
            'Host'                  => $connection['host'] . ':' . $connection['port'],
            'User-Agent'            => 'PHP WebSocket Client',
            'Connection'            => 'upgrade',
            'Upgrade'               => 'websocket',
            'Sec-WebSocket-Key'     => $securityKey,
            'Sec-WebSocket-Version' => 13,
        ];

        // Add authentication
        if ($connection['username'] || $connection['password']) {
            $headers['Authorization'] = 'Basic ' . base64_encode($connection['username'] . ':' . $connection['password']) . self::EOL;
        }

        // Add origin
        if (isset($this->options['origin'])) {
            $headers['Origin'] = $this->options['origin'];
        }

        // Add option headers
        if (isset($this->options['headers'])) {
            $headers = array_merge($headers, $this->options['headers']);
        }

        // Create headers string
        $headerString = 'GET ' . $connection['fullPath'] . ' HTTP/1.1' . self::EOL;
        foreach ($headers as $key => $value) {
            $headerString .= $key . ': ' . $value . self::EOL;
        }
        return $headerString . self::EOL;
    }
}
