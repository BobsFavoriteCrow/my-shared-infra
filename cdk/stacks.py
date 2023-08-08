# Third Party
from aws_cdk import Stack, aws_kms as kms
from constructs import Construct

# My Libraries
from cdk import enums, constructs


class MyDNSSECStack(Stack):
    def __init__(
        self,
        scope: Construct,
        id: str = "my-dnssec-stack",
        *,
        stack_name: str = "my-dnssec-stack",
        **kwargs,
    ) -> None:
        env = constructs.MyEnvironment(region="us-east-1")

        super().__init__(scope, id, env=env, stack_name=stack_name, **kwargs)

        # Add DNSSEC service to my hosted zone
        my_dnssec_service = constructs.MyDNSSECService(
            self,
            "thatsmidnight-dnssec-service",
            hosted_zone_id=enums.HOSTED_ZONE_ID,
        )

        # Create cryptographic key for signing
        my_kms_alias = "thatsmidnight-dnssec-signing-key"
        my_dnssec_key = constructs.MyKmsKey(
            self,
            "thatsmidnight-dnssec-key",
            alias=my_kms_alias,
            key_spec=kms.KeySpec.ECC_NIST_P256,
            key_usage=kms.KeyUsage.SIGN_VERIFY,
        )

        # Give DNSSEC service permissions to use key
        my_dnssec_key.add_to_resource_policy(
            constructs.MyPolicyStatement(
                sid="Allow Route 53 DNSSEC Service",
                principals=[
                    constructs.MyServicePrincipal(
                        "dnssec-route53.amazonaws.com"
                    )
                ],
                actions=[
                    "kms:DescribeKey",
                    "kms:GetPublicKey",
                    "kms:Sign",
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account}
                },
            )
        )
        my_dnssec_key.add_to_resource_policy(
            constructs.MyPolicyStatement(
                sid="Allow Route 53 DNSSEC to CreateGrant",
                principals=[
                    constructs.MyServicePrincipal(
                        "dnssec-route53.amazonaws.com"
                    )
                ],
                actions=["kms:CreateGrant"],
                resources=["*"],
                conditions={
                    "StringEquals": {"aws:SourceAccount": self.account},
                    "Bool": {"kms:GrantIsForAWSResource": True},
                },
            )
        )

        # Create Key Signing Key (KSK) and associate with hosted zone
        my_ksk = constructs.MyKeySigningKey(
            self,
            "my-key-signing-key",
            name="ThatsMidnightDNSSECKSK",
            hosted_zone_id=enums.HOSTED_ZONE_ID,
            kms_service_arn=Stack.of(self).format_arn(
                region=env.region,
                service="kms",
                account=self.account,
                resource="alias",
                resource_name=my_kms_alias,
            ),
        )
        my_ksk.node.add_dependency(my_dnssec_key)
        my_dnssec_service.node.add_dependency(my_ksk)

        # NOTE: There is a *manual* step here that requires you to go to the
        #   AWS Route 53 console to get the DS record in order to establish
        #   a chain of trust. We are storing this value in a repo secret:
        #   `CHAINOFTRUST_DS_RECORD`.
        #   If Route 53 is your registrar, in a new tab go to Registered
        #   Domains, open your domain page, and under DNSSEC status click
        #   Manage Keys. Select the correct algorithm (shown in the
        #   information page) and copy and paste your public key.

        # Add chain of trust DS record to hosted zone
        my_hosted_zone = constructs.MyHostedZone.import_existing(
            self,
            "my-hosted-zone",
            hosted_zone_id=enums.HOSTED_ZONE_ID,
            zone_name=enums.MyDomainName.domain_name.value,
        )
        constructs.MyDSRecord(
            self,
            "my-chainoftrust-dsrecord",
            zone=my_hosted_zone,
            values=[enums.CHAINOFTRUST_DS_RECORD],
            record_name="*",
        )


class MyApiSubdomainStack(Stack):
    def __init__(
        self,
        scope: Construct,
        id: str = "my-api-subdomain-stack",
        *,
        stack_name: str = "my-api-subdomain-stack",
        **kwargs,
    ) -> None:
        env = constructs.MyEnvironment()

        super().__init__(scope, id, env=env, stack_name=stack_name, **kwargs)

        # TODO: do stuff
