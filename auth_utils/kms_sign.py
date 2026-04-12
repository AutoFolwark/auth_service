import asyncio
import json
import base64

import aioboto3
import redis
from redis import Redis

from config import aws_boto_session_kwargs, settings
from cryptography.hazmat.primitives import serialization


class Signer:
    def __init__(self, session: aioboto3.Session, redis_client: Redis, key_arn: str, signing_algorithm: str = None,
                 cache_ttl: int = 3600):
        self.session = session
        self.redis_client = redis_client
        self.key_arn = key_arn
        self.signing_algorithm = signing_algorithm
        self.cache_ttl = cache_ttl
        self.redis_key = f"kms_key_info:{key_arn}"
        self.public_key_cache_key = f"kms_public_key:{key_arn}"

    async def sign(self, message: bytes) -> bytes:
        if self.signing_algorithm is None:
            info = await self.get_key_info()
            algos = info.get("SigningAlgorithms") or []
            if not algos:
                raise ValueError("No available signing algorithms for the key")
            self.signing_algorithm = algos[0]
        async with self.session.client("kms") as client:
            response = await client.sign(
                KeyId=self.key_arn,
                Message=message,
                MessageType="RAW",
                SigningAlgorithm=self.signing_algorithm,
            )
            return response["Signature"]

    async def get_key_info(self):
        cached_info = await self.redis_client.get(self.redis_key)
        if cached_info:
            try:
                info = json.loads(cached_info)
                return info
            except json.JSONDecodeError:
                await self.redis_client.delete(self.redis_key)
        
        async with self.session.client("kms") as client:
            key_info = await client.get_public_key(KeyId=self.key_arn)
            try:
                cache_info = {k: v for k, v in key_info.items() if k != "PublicKey"}
                
                await self.redis_client.setex(
                    self.redis_key,
                    self.cache_ttl,
                    json.dumps(cache_info, default=str)
                )
                
                # Cache public key separately as base64 string
                if "PublicKey" in key_info:
                    public_key_b64 = base64.b64encode(key_info["PublicKey"]).decode('utf-8')
                    await self.redis_client.setex(
                        self.public_key_cache_key,
                        self.cache_ttl,
                        public_key_b64
                    )
                    
            except Exception as e:
                print(f"Failed to cache key info: {e}")
            return key_info

    async def get_public_key(self) -> bytes:
        cached_key = await self.redis_client.get(self.public_key_cache_key)
        if cached_key:
            try:
                return base64.b64decode(cached_key)
            except Exception as e:
                print(f"Failed to decode cached public key: {e}")
                await self.redis_client.delete(self.public_key_cache_key)

        async with self.session.client("kms") as client:
            key_info = await client.get_public_key(KeyId=self.key_arn)
            public_key_bytes = key_info.get("PublicKey")
            if not public_key_bytes:
                raise ValueError("No public key found in KMS key info")

            try:
                public_key_b64 = base64.b64encode(public_key_bytes).decode('utf-8')
                await self.redis_client.setex(
                    self.public_key_cache_key,
                    self.cache_ttl,
                    public_key_b64
                )
            except Exception as e:
                print(f"Failed to cache public key: {e}")
            
            return public_key_bytes
    
    async def get_public_key_pem(self) -> str:
        try:
            public_key_der = await self.get_public_key()

            if not isinstance(public_key_der, bytes):
                raise ValueError(f"Expected bytes, got {type(public_key_der)}")

            public_key = serialization.load_der_public_key(public_key_der)

            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            return pem_public_key.decode('utf-8')
            
        except Exception as e:
            await self.redis_client.delete(self.public_key_cache_key)
            await self.redis_client.delete(self.redis_key)

            public_key_der = await self.get_public_key()
            public_key = serialization.load_der_public_key(public_key_der)
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            return pem_public_key.decode('utf-8')


if __name__ == "__main__":
    async def main():
        kms_session = aioboto3.Session(**aws_boto_session_kwargs())
        get_redis_client = await redis.asyncio.from_url(settings.REDIS_URL, decode_responses=True)
        signer = Signer(kms_session, key_arn=settings.AWS_KMS_KEY_ARN, redis_client=get_redis_client)
        print(await signer.get_public_key_pem())
        signature = await signer.sign(b"hello world")
    asyncio.run(main())