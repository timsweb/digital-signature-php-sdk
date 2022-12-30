<?php

namespace Ebay\DigitalSignature;

use Mapper\ModelMapper;

class Signature {

    private SignatureConfig $signatureConfig;
    private SignatureService $signatureService;

    public static function fromFile(string $configPath) : self
    {
        $instance = new self();
        $instance->loadSignatureConfigFromFile($configPath);
        return $instance;
    }

    public static function fromConfig(array $config) : self
    {
        $instance = new self();
        $instance->loadSignatureConfig((object)$config);
        return $instance;
    }

    public function __construct()
    {
        $this->signatureService = new SignatureService();
    }


    /**
     * Returns an array with all required headers. Add this to your HTTP request
     *
     * @param array $headers request headers
     * @param string $endpoint URI of the request
     * @param string $method POST, GET, PUT, etc.
     * @param string|null $body body
     * @return array All headers including the initially transmitted
     */
    public function generateSignatureHeaders(array $headers, string $endpoint, string $method, string $body = null): array {
        if (!is_null($body)) {
            $headers["Content-Digest"] = $this->signatureService->generateContentDigest($body, $this->signatureConfig);
        }
        $timestamp = time();
        $headers["x-ebay-signature-key"] = $this->signatureService->generateSignatureKey($this->signatureConfig);
        $headers["Signature-Input"] = $this->signatureService->generateSignatureInput($timestamp, $this->signatureConfig);
        $headers["Signature"] = $this->signatureService->generateSignature($headers, $method, $endpoint, $timestamp, $this->signatureConfig);
        $headers["x-ebay-enforce-signature"] = "true";

        return $headers;
    }

    private function loadSignatureConfigFromFile(string $configPath): void
    {
        $json = file_get_contents($configPath);
        $jsonDecodedObj = json_decode($json, false);
        $this->loadSignatureConfig($jsonDecodedObj);
    }



    /**
     * Load config value into SignatureConfig Object
     *
     * @param string $configPath config path
     */
    private function loadSignatureConfig($config)
    {
        $mapper = new ModelMapper();
        $this->signatureConfig = new SignatureConfig();
        $mapper->map($jsonDecodedObj, $this->signatureConfig);

        if (is_null($this->signatureConfig->privateKeyStr) && !is_null($this->signatureConfig->privateKey)) {
            $this->signatureConfig->privateKeyStr = file_get_contents($this->signatureConfig->privateKey);
        }
    }
}