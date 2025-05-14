<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Tests\Provider;

use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Result\CheckResult;

final class GoogleSafeBrowsingProviderTest extends TestCase
{
    public function testCheckReturnsSafeResultWhenNoThreatFound(): void
    {
        $mock = new MockHandler([
            new Response(200, [], json_encode([
                'matches' => []
            ]))
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $provider = new GoogleSafeBrowsingProvider(
            'test-api-key',
            $client,
            new HttpFactory(),
            new HttpFactory()
        );

        $result = $provider->check('https://example.com');

        $this->assertInstanceOf(CheckResult::class, $result);
        $this->assertTrue($result->isSafe());
        $this->assertEmpty($result->getThreats());
    }

    public function testCheckReturnsUnsafeResultWhenThreatFound(): void
    {
        $mockResponse = [
            'matches' => [
                [
                    'threatType' => 'MALWARE',
                    'platformType' => 'ANY_PLATFORM',
                    'threat' => [
                        'url' => 'https://malicious-example.com'
                    ]
                ]
            ]
        ];

        $mock = new MockHandler([
            new Response(200, [], json_encode($mockResponse))
        ]);

        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $provider = new GoogleSafeBrowsingProvider(
            'test-api-key',
            $client,
            new HttpFactory(),
            new HttpFactory()
        );

        $result = $provider->check('https://malicious-example.com');

        $this->assertInstanceOf(CheckResult::class, $result);
        $this->assertFalse($result->isSafe());
        $this->assertCount(1, $result->getThreats());
        $this->assertSame('MALWARE', $result->getThreats()[0]->getType());
        $this->assertSame('google_safebrowsing', $result->getThreats()[0]->getProviderName());
    }

    public function testCheckBatchCallsCheckForEachUrl(): void
    {
        $mockResponses = [
            new Response(200, [], json_encode(['matches' => []])),
            new Response(200, [], json_encode(['matches' => []]))
        ];

        $mock = new MockHandler($mockResponses);
        $handlerStack = HandlerStack::create($mock);
        $client = new Client(['handler' => $handlerStack]);

        $provider = new GoogleSafeBrowsingProvider(
            'test-api-key',
            $client,
            new HttpFactory(),
            new HttpFactory()
        );

        $urls = [
            'https://example.com',
            'https://another-example.com'
        ];

        $results = $provider->checkBatch($urls);

        $this->assertCount(2, $results);
        $this->assertArrayHasKey('https://example.com', $results);
        $this->assertArrayHasKey('https://another-example.com', $results);
        $this->assertInstanceOf(CheckResult::class, $results['https://example.com']);
        $this->assertInstanceOf(CheckResult::class, $results['https://another-example.com']);
    }

    public function testGetNameReturnsCorrectProviderName(): void
    {
        $provider = new GoogleSafeBrowsingProvider('test-api-key');

        $this->assertSame('google_safebrowsing', $provider->getName());
    }
}
