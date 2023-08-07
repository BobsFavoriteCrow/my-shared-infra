# Standard Library
import builtins
from os import getenv
from typing import List

# Third Party
from aws_cdk import (
    Environment,
    RemovalPolicy,
    aws_iam as iam,
    aws_kms as kms,
    aws_route53 as route53,
)
from constructs import Construct


class MyEnvironment(Environment):
    def __init__(self, *, account: str = None, region: str = None) -> None:
        account = getenv("AWS_ACCOUNT_ID") if not account else account
        region = getenv("AWS_DEFAULT_REGION") if not region else region
        super().__init__(account=account, region=region)


class MyHostedZone(route53.HostedZone):
    @classmethod
    def import_existing(
        cls, scope: Construct, id: str, hosted_zone_id: str, zone_name: str
    ) -> route53.HostedZone:
        return route53.HostedZone.from_hosted_zone_attributes(
            scope, id, hosted_zone_id=hosted_zone_id, zone_name=zone_name
        )

    def __init__(self, scope: Construct, id: str, zone_name: str) -> None:
        super().__init__(scope, id, zone_name=zone_name)


class MyDNSSECService(route53.CfnDNSSEC):
    def __init__(
        self,
        scope: Construct,
        id: str,
        hosted_zone_id: str,
    ) -> None:
        super().__init__(scope, id, hosted_zone_id=hosted_zone_id)
        self.apply_removal_policy(RemovalPolicy.DESTROY)


class MyKmsKey(kms.Key):
    def __init__(
        self,
        scope: Construct,
        id: str,
        alias: str = None,
        key_spec: str = kms.KeySpec.SYMMETRIC_DEFAULT,
        key_usage: str = kms.KeyUsage.ENCRYPT_DECRYPT,
        enable_key_rotation: bool = False,
        removal_policy: str = RemovalPolicy.DESTROY,
    ):
        super().__init__(
            scope,
            id,
            alias=alias,
            key_spec=key_spec,
            key_usage=key_usage,
            enable_key_rotation=enable_key_rotation,
            removal_policy=removal_policy,
        )


class MyKeySigningKey(route53.CfnKeySigningKey):
    def __init__(
        self,
        scope: Construct,
        id: str,
        name: str,
        hosted_zone_id: str,
        kms_service_arn: str,
        status: str = "ACTIVE",
    ) -> None:
        super().__init__(
            scope,
            id,
            hosted_zone_id=hosted_zone_id,
            name=name,
            key_management_service_arn=kms_service_arn,
            status=status,
        )
        self.apply_removal_policy(RemovalPolicy.DESTROY)


class MyServicePrincipal(iam.ServicePrincipal):
    def __init__(self, service: str, **kwargs) -> None:
        super().__init__(service=service, **kwargs)


class MyPolicyStatement(iam.PolicyStatement):
    def __init__(
        self,
        sid: str,
        actions: List[str],
        resources: List[str],
        **kwargs,
    ) -> None:
        super().__init__(
            sid=sid,
            actions=actions,
            resources=resources,
            **kwargs,
        )
