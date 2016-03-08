<?php

namespace Chadicus\Slim\OAuth2\Middleware;

/**
 * Unit tests for the \Chadicus\Slim\OAuth2\Middleware\Authorization class.
 *
 * @coversDefaultClass \Chadicus\Slim\OAuth2\Middleware\Authorization
 * @covers ::<private>
 * @covers ::__construct
 */
final class AuthorizationTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Empty function to be used within tests.
     *
     * @var callable
     */
    private static $emptyFunction;

    /**
     * Verify basic behavior of call()
     *
     * @test
     * @covers ::call
     *
     * @return void
     */
    public function call()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state' => true,
                'allow_implicit' => false,
                'access_lifetime' => 3600
            ]
        );

        $env=\Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $slim->get('/foo', self::$emptyFunction)->add(new Authorization($slim, $server));

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        $slim($request, $response);
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => null,
            ],
            $slim->getContainer()['token']
        );
    }

    /**
     * Verify behavior of call with expired access token
     *
     * @test
     * @covers ::call
     *
     * @return void
     *
     * @throws \Exception Thrown only if /foo route is executed.
     */
    public function callExpiredToken()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => strtotime('-1 minute'),
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env=\Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $slim->get('/foo', function () {
            throw new \Exception('This will not get executed');
        })->add(new Authorization($slim, $server));

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        try {
            $response = $slim($request, $response);
        } catch (\Exception $e) {
            //ignore this error
            var_dump($e);
            $this->assertInstanceOf('\Exception', $e);
        }

        $this->assertSame(401, $response->getStatusCode());
        $this->assertSame(
            '{"error":"expired_token","error_description":"The access token provided has expired"}',
            $response->getBody()->getContents()
        );
    }

    /**
     * Verify basic behaviour of withRequiredScope().
     *
     * @test
     * @covers ::call
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScope()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'allowFoo anotherScope',
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env = \Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($slim, $server);
        $slim->get('/foo', self::$emptyFunction)->add($authorization->withRequiredScope(['allowFoo']));

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        $response = $slim($request, $response);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'allowFoo anotherScope',
            ],
            $slim->getContainer()['token']
        );
    }

    /**
     * Verify behaviour of withRequiredScope() with insufficient scope.
     *
     * @test
     * @covers ::call
     * @covers ::withRequiredScope
     *
     * @return void
     */
    public function withRequiredScopeInsufficientScope()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'aScope anotherScope',
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env = \Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($slim, $server);
        $slim->get('/foo', self::$emptyFunction)->add($authorization->withRequiredScope(['allowFoo']));

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        $response = $slim($request, $response);

        $this->assertSame(403, $response->getStatusCode());
        $this->assertSame(
            '{"error":"insufficient_scope","error_description":"The request requires higher privileges than provided '
            . 'by the access token"}',
            $response->getBody()->getContents()
        );
    }

    /**
     * Verify Authorization is invokeable.
     *
     * @test
     * @covers ::__invoke
     *
     * @return void
     */
    public function invoke()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => null,
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env = \Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($slim, $server);
        $slim->get('/foo', self::$emptyFunction)->add($authorization);

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        /** @var \Slim\Http\Response $response */
        $response = $slim($request, $response);

        $this->assertSame(200, $response->getStatusCode());
    }

    /**
     * Verify behavior of call without access token
     *
     * @test
     * @covers ::call
     *
     * @return void
     */
    public function callNoTokenProvided()
    {
        $storage = new \OAuth2\Storage\Memory([]);

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env = \Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($slim, $server);
        $slim->get('/foo', function () {
            echo json_encode(['success' => true]);
        })->add($authorization);

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        try {
            /** @var \Slim\Http\Response $response */
            $response = $slim($request, $response);
        } catch (\Exception $e) {
//            $this->assertInstanceOf('\Slim\Exception\Stop', $e);
        }

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * Verify call with scopes using OR logic
     *
     * @test
     * @covers ::call
     *
     * @return void
     */
    public function callWithEitherScope()
    {
        $storage = new \OAuth2\Storage\Memory(
            [
                'access_tokens' => [
                    'atokenvalue' => [
                        'access_token' => 'atokenvalue',
                        'client_id' => 'a client id',
                        'user_id' => 'a user id',
                        'expires' => 99999999900,
                        'scope' => 'basicUser withPermission anExtraScope',
                    ],
                ],
            ]
        );

        $server = new \OAuth2\Server(
            $storage,
            [
                'enforce_state'   => true,
                'allow_implicit'  => false,
                'access_lifetime' => 3600
            ]
        );

        $env = \Slim\Http\Environment::mock(
            [
                'CONTENT_TYPE' => 'application/json',
                'REQUEST_URI' => '/foo',
            ]
        );

        $slim = self::getSlimInstance();
        $authorization = new Authorization($slim, $server);
        $slim->get(
            '/foo',
            self::$emptyFunction
        )->add($authorization->withRequiredScope(['superUser', ['basicUser', 'withPermission']]));

        $request = \Slim\Http\Request::createFromEnvironment($env);
        $request = $request->withHeader('Authorization', 'Bearer atokenvalue');
        $response = new \Slim\Http\Response();

        /** @var \Slim\Http\Response $response */
        $response = $slim($request, $response);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(
            [
                'access_token' => 'atokenvalue',
                'client_id' => 'a client id',
                'user_id' => 'a user id',
                'expires' => 99999999900,
                'scope' => 'basicUser withPermission anExtraScope',
            ],
            $slim->getContainer()['token']
        );
    }

    /**
     * Helper method to return a new instance of \Slim\Slim.
     *
     * @return \Slim\App
     */
    private static function getSlimInstance()
    {
        return new \Slim\App();
    }

    /**
     * Prepare each test.
     *
     * @return void
     */
    protected function setUp()
    {
        //empty function to use within tests
        self::$emptyFunction = function () {
        };
        ob_start();
    }

    /**
     * Perform cleanup after each test.
     *
     * @return void
     */
    protected function tearDown()
    {
        ob_end_clean();
    }
}
