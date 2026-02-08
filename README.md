# Ultimate Link Checker

![License](https://img.shields.io/github/license/qdenka/ultimatelinkchecker)
![PHP Version](https://img.shields.io/badge/php-8.1%2B-blue.svg)

A powerful, flexible PHP library for checking links against multiple security services.

## Features

- 🔍 Check URLs against multiple security services with a unified API
- 🚀 Supports Google Safe Browsing, Yandex Safe Browsing, Facebook, VirusTotal, and more
- ⚡ Asynchronous checking capability with Promise-based API
- 🔧 Easily extensible to add new providers
- 💾 Optional caching of results to reduce API calls
- 📊 Detailed threat information and comprehensive reports
- 🔄 Configurable retry logic with incremental backoff
- 📝 PSR-3 compatible logging

## Installation

```bash
composer require qdenka/ultimatelinkchecker
```

## Requirements

- PHP 8.1 or higher
- Composer
- API keys for the services you want to use

## Quick Start

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;

// Create the link checker with a provider
$checker = new UltimateLinkChecker();
$checker->addProvider(new GoogleSafeBrowsingProvider('your-api-key'));

// Check a single URL
$result = $checker->check('https://example.com');

// Check if it's safe
if ($result->isSafe()) {
    echo "The URL is safe!";
} else {
    echo "Threats found:" . PHP_EOL;
    foreach ($result->getThreats() as $providerName => $threats) {
        foreach ($threats as $threat) {
            echo "  [{$providerName}] " . $threat->getDescription() . PHP_EOL;
        }
    }
}

// Check multiple URLs at once
$results = $checker->checkBatch([
    'https://example.com',
    'https://another-example.com'
]);

foreach ($results as $url => $result) {
    echo "$url: " . ($result->isSafe() ? "Safe" : "Unsafe") . PHP_EOL;
}
```

## Using Multiple Providers

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\VirusTotalProvider;

$checker = new UltimateLinkChecker();

// Add multiple providers
$checker->addProvider(new GoogleSafeBrowsingProvider('google-api-key'));
$checker->addProvider(new YandexSafeBrowsingProvider('yandex-api-key'));
$checker->addProvider(new VirusTotalProvider('virustotal-api-key'));

// Check against all providers
// CONSENSUS_ANY = unsafe if ANY provider flags it (strictest, default)
// CONSENSUS_ALL = unsafe only if ALL providers flag it (most lenient)
// CONSENSUS_MAJORITY = unsafe if majority flags it
$result = $checker->check(
    url: 'https://example.com',
    consensus: UltimateLinkChecker::CONSENSUS_ANY
);

if ($result->isSafe()) {
    echo "The URL is considered safe by the selected consensus method";
} else {
    echo "The URL is unsafe" . PHP_EOL;

    foreach ($result->getThreats() as $providerName => $threats) {
        foreach ($threats as $threat) {
            echo "  [{$providerName}] " . $threat->getDescription() . PHP_EOL;
        }
    }
}
```

## Asynchronous Checking

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;

$checker = new UltimateLinkChecker();
$checker->addProvider(new GoogleSafeBrowsingProvider('google-api-key'));
$checker->addProvider(new YandexSafeBrowsingProvider('yandex-api-key'));

// Get promises for multiple URLs
$promises = $checker->checkBatchAsync([
    'https://example1.com',
    'https://example2.com',
    'https://example3.com',
]);

// Process results as they come in
foreach ($promises as $url => $promise) {
    $promise->then(
        function ($result) use ($url) {
            echo "$url is " . ($result->isSafe() ? "safe" : "unsafe") . PHP_EOL;
        },
        function ($error) use ($url) {
            echo "Error checking $url: " . $error->getMessage() . PHP_EOL;
        }
    );
}
```

## Available Providers

| Provider | Class | Description |
|---|---|---|
| Google Safe Browsing | `GoogleSafeBrowsingProvider` | Google's threat database |
| Yandex Safe Browsing | `YandexSafeBrowsingProvider` | Yandex's threat database |
| VirusTotal | `VirusTotalProvider` | Multi-engine antivirus aggregator |
| Facebook URL Security | `FacebookProvider` | Facebook URL sharing safety |
| PhishTank | `PhishTankProvider` | Community phishing database |
| OPSWAT MetaDefender | `OPSWATProvider` | Multi-scanning URL reputation |
| Cisco Talos | `CiscoTalosProvider` | Cisco threat intelligence |
| IPQualityScore | `IPQualityScoreProvider` | URL reputation scoring |

## Using the Provider Factory

```php
use Qdenka\UltimateLinkChecker\Factory\ProviderFactory;
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;

$checker = new UltimateLinkChecker();

// Create providers by name with optional timeout and retries
$checker->addProvider(ProviderFactory::createProvider('google_safebrowsing', 'api-key', timeout: 10.0, retries: 2));
$checker->addProvider(ProviderFactory::createProvider('virustotal', 'api-key'));
$checker->addProvider(ProviderFactory::createProvider('facebook', 'app_id|app_secret'));

// List all available providers
$available = ProviderFactory::getAvailableProviders();
```

## Creating Your Own Provider

```php
use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use Qdenka\UltimateLinkChecker\Result\Threat;

class MyCustomProvider implements ProviderInterface
{
    public function getName(): string
    {
        return 'my_custom_provider';
    }

    public function check(string $url): CheckResult
    {
        $result = new CheckResult($url);

        // Your implementation to check the URL
        $isSafe = true; // Your logic here

        if (!$isSafe) {
            $threat = new Threat(
                type: 'MALWARE',
                platform: 'ANY_PLATFORM',
                description: 'This URL contains malware'
            );
            $result->addThreat($this->getName(), $threat);
        }

        return $result;
    }

    public function checkBatch(array $urls): array
    {
        $results = [];
        foreach ($urls as $url) {
            $results[$url] = $this->check($url);
        }
        return $results;
    }
}
```

## Advanced Configuration

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Cache\RedisCacheAdapter;
use Qdenka\UltimateLinkChecker\Config\CheckerConfig;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// Create a PSR-3 logger
$logger = new Logger('link-checker');
$logger->pushHandler(new StreamHandler('path/to/your.log'));

// Create a configuration
$config = new CheckerConfig();
$config->setCacheAdapter(new RedisCacheAdapter($redisClient));
$config->setCacheTtl(3600); // Cache results for 1 hour
$config->setTimeout(5.0); // 5 second timeout for API calls
$config->setRetries(2); // Retry failed API calls twice
$config->setLogger($logger); // PSR-3 logger

// Create checker with config
$checker = new UltimateLinkChecker($config);

// Create providers with timeout/retries from config
$checker->addProvider(new GoogleSafeBrowsingProvider(
    apiKey: 'api-key',
    timeout: $config->getTimeout(),
    retries: $config->getRetries()
));

// Now all checks will use the configured cache, timeout, and logging settings
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

Created with ❤️ by [qdenka](https://github.com/qdenka)
