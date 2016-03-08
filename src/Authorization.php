<?php
namespace Chadicus\Slim\OAuth2\Middleware;

use OAuth2;
use Chadicus\Slim\OAuth2\Http\MessageBridge;
use Slim\App;
use Symfony\Component\Filesystem\Exception\IOException;

/**
 * Slim Middleware to handle OAuth2 Authorization.
 */
class Authorization
{
    /**
     * The slim framework application instance.
     *
     * @var App
     */
    private $app;


    /**
     * OAuth2 Server
     *
     * @var OAuth2\Server
     */
    private $server;

    /**
     * Create a new instance of the Authroization middleware
     *
     * @param App $app
     * @param OAuth2\Server $server The configured OAuth2 server.
     */
    public function __construct(App $app, OAuth2\Server $server)
    {
        $this->app = $app;
        $this->server = $server;
    }

    /**
     * Verify request contains valid access token.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $req
     * @param \Psr\Http\Message\ResponseInterface $res
     * @param $next
     * @param array $scopes Scopes required for authorization. $scopes can be given as an array of arrays. OR logic will
     *                      use with each grouping. Example: Given ['superUser', ['basicUser', 'aPermission']], the
     *                      request will be verified if the request token has 'superUser' scope OR 'basicUser' and
     *                      'aPermission' as its scope.
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function call($req, $res, $next, array $scopes = [null])
    {
        if (!$this->verify($req, $scopes)) {
            MessageBridge::mapResponse($this->server->getResponse(), $res);
            return $res;
        } //@codeCoverageIgnore since stop() throws

        $container = $this->app->getContainer();
        $container['token'] = $this->server->getResourceController()->getToken();

        if ($next !== null) {
            $res = $next($req, $res);
        }
        return $res;
    }

    /**
     * Helper method to verify a resource request, allowing return early on success cases
     *
     * @param \Psr\Http\Message\ServerRequestInterface $req
     * @param array $scopes Scopes required for authorization.
     * @return bool True if the request is verified, otherwise false
     */
    private function verify($req, array $scopes = [null])
    {
        foreach ($scopes as $scope) {
            if (is_array($scope)) {
                $scope = implode(' ', $scope);
            }

            $oauth2Request = MessageBridge::newOauth2Request($req);
            if ($this->server->verifyResourceRequest($oauth2Request, null, $scope)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Call this class as a function.
     *
     * @param \Psr\Http\Message\ServerRequestInterface $req
     * @param \Psr\Http\Message\ResponseInterface $res
     * @param $next
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function __invoke($req, $res, $next)
    {
        return $this->call($req, $res, $next);
    }

    /**
     * Returns a callable function to be used as a authorization middleware with a specified scope.
     *
     * @param array $scopes Scopes require for authorization.
     *
     * @return callable
     */
    public function withRequiredScope(array $scopes)
    {
        $auth = $this;
        return function ($req, $res, $next) use ($auth, $scopes) {
            return $auth->call($req, $res, $next, $scopes);
        };
    }
}
