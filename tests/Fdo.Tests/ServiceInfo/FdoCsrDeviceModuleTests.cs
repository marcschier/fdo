using System;
using System.Collections.Generic;
using System.Formats.Cbor;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Fdo.Enrollment;
using Fdo.Serialization;
using Fdo.ServiceInfo;
using Entry = Fdo.Serialization.FdoServiceInfoCodec.Entry;

namespace Fdo.Tests.ServiceInfo;

[UnsupportedOSPlatform("browser")]
public sealed class FdoCsrDeviceModuleTests
{
    [Test]
    [Arguments(false, false)]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task DiscoveryWaitsForAHostSelectedCsrAfterOptionalCaDistribution(
        bool withCaCertificates, bool isReenrollment)
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(
            default, ushort.MaxValue, requestCaCertificates: withCaCertificates,
            isReenrollment: isReenrollment, requestCsrAttributes: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        IReadOnlyList<Entry> outgoing = Decode(await processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }))));
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:active");
        if (withCaCertificates)
        {
            await Assert.That(FdoCsrCaCertificatesCodec.DecodeRequest(outgoing[1])).IsEqualTo(281UL);
            module.MarkRequestSent();
            outgoing = Decode(await processor.ProcessAsync(Encode(
                codec.EncodeCaCertificates(new FdoCaCertificates([fixture.Certificate])))));
        }
        else
        {
            outgoing = [outgoing[1]];
        }

        await Assert.That(outgoing.Count).IsEqualTo(1);
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:csrattrs-req");
        FdoCsrAttributesRequestCodec.Validate(outgoing[0]);
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCsrAttributes())).IsTrue();
        module.MarkRequestSent();

        var attributes = new FdoCsrAttributes(new byte[] { 0x30, 0x00 });
        IReadOnlyList<Entry> afterAttributes = Decode(await processor.ProcessAsync(Encode(
            codec.EncodeCsrAttributes(attributes))));
        await Assert.That(afterAttributes.Count).IsEqualTo(0);
        await Assert.That(module.CopyPendingCsrAttributes().Entries.Count).IsEqualTo(0);
        byte[] selected = (byte[])fixture.Request.Clone();
        Entry request = module.PrepareEnrollmentRequest(selected);
        Array.Clear(selected);
        await Assert.That(request.Key).IsEqualTo(
            isReenrollment ? "fdo.csr:simplereenroll-req" : "fdo.csr:simpleenroll-req");
        await Assert.That(codec.DecodeRequest(request, isReenrollment).AsSpan()
            .SequenceEqual(fixture.Request)).IsTrue();
        ClearExposedMemory(module.CopyEnrollmentRequest());
        await Assert.That(module.CopyEnrollmentRequest().Span.SequenceEqual(fixture.Request)).IsTrue();
        module.MarkRequestSent();
        await processor.ProcessAsync(Encode(codec.EncodeResponse(fixture.Request, fixture.Certificate, isReenrollment)));

        await Assert.That(module.CopyPendingCertificate().Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task DiscoveryRejectsEarlyAndDuplicateAttributeResponses()
    {
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        Entry attributes = codec.EncodeCsrAttributes(new FdoCsrAttributes(new byte[] { 0x30, 0x00 }));
        var early = new FdoCsrDeviceModule(default, ushort.MaxValue, requestCsrAttributes: true);
        var first = new FdoDeviceServiceInfoProcessor([early]);
        await first.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        await CatchAsync<InvalidOperationException>(() => first.ProcessAsync(Encode(attributes)));
        await Assert.That(first.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => early.CopyPendingCsrAttributes())).IsTrue();

        var duplicate = new FdoCsrDeviceModule(default, ushort.MaxValue, requestCsrAttributes: true);
        var second = new FdoDeviceServiceInfoProcessor([duplicate]);
        await second.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        duplicate.MarkRequestSent();
        await CatchAsync<InvalidOperationException>(() => second.ProcessAsync(Encode(attributes, attributes)));
        await Assert.That(second.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => duplicate.CopyPendingCsrAttributes())).IsTrue();
    }

    [Test]
    public async Task UnsupportedDiscoveryAndInvalidSelectedCsrStopEnrollment()
    {
        using var fixture = new Fixture();
        var unsupported = new FdoCsrDeviceModule(default, ushort.MaxValue, requestCsrAttributes: true);
        var first = new FdoDeviceServiceInfoProcessor([unsupported]);
        await first.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        unsupported.MarkRequestSent();
        FdoCsrModuleException error = await CatchAsync<FdoCsrModuleException>(() =>
            first.ProcessAsync(Encode(new Entry("fdo.csr:error", new byte[] { 0x03 }))));
        await Assert.That(error.ErrorCode).IsEqualTo(3UL);
        await Assert.That(first.IsFaulted).IsTrue();

        var invalid = new FdoCsrDeviceModule(default, ushort.MaxValue, requestCsrAttributes: true);
        var second = new FdoDeviceServiceInfoProcessor([invalid]);
        await second.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        invalid.MarkRequestSent();
        await second.ProcessAsync(Encode(new FdoCsrBase64TextCodec(ushort.MaxValue)
            .EncodeCsrAttributes(new FdoCsrAttributes(new byte[] { 0x30, 0x00 }))));
        await Assert.That(Throws<CryptographicException>(() =>
            invalid.PrepareEnrollmentRequest(new byte[] { 0x30, 0x00 }))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() =>
            invalid.PrepareEnrollmentRequest(fixture.Request))).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => invalid.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task OwnerActivationProducesAvailabilityAndRequestThenStagesTheMatchingCertificate()
    {
        using var fixture = new Fixture();
        byte[] expectedRequest = (byte[])fixture.Request.Clone();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        Array.Fill(fixture.Request, (byte)0);

        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
        IReadOnlyList<Entry> outgoing = Decode(await processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }))));
        await Assert.That(outgoing.Count).IsEqualTo(2);
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:active");
        await Assert.That(Convert.ToHexString(outgoing[0].EncodedValue.Span)).IsEqualTo("F5");
        await Assert.That(outgoing[1].Key).IsEqualTo("fdo.csr:simpleenroll-req");
        await Assert.That(Convert.ToHexString(codec.DecodeRequest(outgoing[1])))
            .IsEqualTo(Convert.ToHexString(expectedRequest));

        module.MarkRequestSent();
        Entry response = codec.EncodeResponse(expectedRequest, fixture.Certificate);
        IReadOnlyList<Entry> afterResponse = Decode(await processor.ProcessAsync(Encode(response)));
        ReadOnlyMemory<byte> pending = module.CopyPendingCertificate();
        await Assert.That(afterResponse.Count).IsEqualTo(0);
        await Assert.That(Convert.ToHexString(pending.Span)).IsEqualTo(Convert.ToHexString(fixture.Certificate));
        ClearExposedMemory(pending);
        await Assert.That(Convert.ToHexString(module.CopyPendingCertificate().Span))
            .IsEqualTo(Convert.ToHexString(fixture.Certificate));
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task ReenrollmentUsesItsOwnRequestAndResponseAfterActivation(bool withCaCertificates)
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue,
            requestCaCertificates: withCaCertificates, isReenrollment: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        IReadOnlyList<Entry> outgoing = Decode(await processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }))));
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:active");
        if (withCaCertificates)
        {
            await Assert.That(FdoCsrCaCertificatesCodec.DecodeRequest(outgoing[1])).IsEqualTo(281UL);
            module.MarkRequestSent();
            outgoing = Decode(await processor.ProcessAsync(Encode(
                codec.EncodeCaCertificates(new FdoCaCertificates([fixture.Certificate])))));
        }
        else
        {
            outgoing = [outgoing[1]];
        }

        await Assert.That(outgoing.Count).IsEqualTo(1);
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:simplereenroll-req");
        await Assert.That(codec.DecodeRequest(outgoing[0], true).AsSpan().SequenceEqual(fixture.Request)).IsTrue();
        module.MarkRequestSent();
        IReadOnlyList<Entry> completed = Decode(await processor.ProcessAsync(Encode(
            codec.EncodeResponse(fixture.Request, fixture.Certificate, true))));

        await Assert.That(completed.Count).IsEqualTo(0);
        await Assert.That(module.CopyPendingCertificate().Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task ReenrollmentRejectsAnInitialEnrollmentResponse()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, isReenrollment: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        await CatchAsync<NotSupportedException>(() => processor.ProcessAsync(Encode(
            codec.EncodeResponse(fixture.Request, fixture.Certificate))));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task CaDistributionAfterActivationPrecedesTheEnrollmentRequest()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        var material = new FdoCaCertificates([fixture.Certificate]);

        IReadOnlyList<Entry> outgoing = Decode(await processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }))));
        await Assert.That(outgoing.Count).IsEqualTo(2);
        await Assert.That(outgoing[0].Key).IsEqualTo("fdo.csr:active");
        await Assert.That(FdoCsrCaCertificatesCodec.DecodeRequest(outgoing[1])).IsEqualTo(281UL);
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCaCertificates())).IsTrue();
        module.MarkRequestSent();

        IReadOnlyList<Entry> enrollment = Decode(await processor.ProcessAsync(Encode(
            codec.EncodeCaCertificates(material))));
        await Assert.That(enrollment.Count).IsEqualTo(1);
        await Assert.That(codec.DecodeRequest(enrollment[0]).AsSpan().SequenceEqual(fixture.Request)).IsTrue();
        await Assert.That(module.CopyPendingCaCertificates().Certificates[0].Span
            .SequenceEqual(fixture.Certificate)).IsTrue();
        module.MarkRequestSent();
        IReadOnlyList<Entry> completed = Decode(await processor.ProcessAsync(Encode(
            codec.EncodeResponse(fixture.Request, fixture.Certificate))));

        await Assert.That(completed.Count).IsEqualTo(0);
        await Assert.That(module.CopyPendingCertificate().Span.SequenceEqual(fixture.Certificate)).IsTrue();
        await Assert.That(processor.IsFaulted).IsFalse();
    }

    [Test]
    public async Task RejectsCaMaterialBeforeActivationOrBeforeTheRequestIsSent()
    {
        using var fixture = new Fixture();
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        Entry caResponse = codec.EncodeCaCertificates(new FdoCaCertificates([fixture.Certificate]));
        var beforeActivation = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var first = new FdoDeviceServiceInfoProcessor([beforeActivation]);
        await CatchAsync<CborContentException>(() => first.ProcessAsync(Encode(caResponse)));
        await Assert.That(first.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => beforeActivation.CopyPendingCaCertificates())).IsTrue();

        var beforeSend = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var second = new FdoDeviceServiceInfoProcessor([beforeSend]);
        await CatchAsync<InvalidOperationException>(() => second.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }), caResponse)));
        await Assert.That(second.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => beforeSend.CopyPendingCaCertificates())).IsTrue();
    }

    [Test]
    public async Task RejectsAnEnrollmentResponseWhileAwaitingCaMaterial()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        await CatchAsync<NotSupportedException>(() => processor.ProcessAsync(Encode(
            codec.EncodeResponse(fixture.Request, fixture.Certificate))));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCaCertificates())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task ReportsAnUnsupportedCaFormatWithoutStartingEnrollment()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        FdoCsrModuleException error = await CatchAsync<FdoCsrModuleException>(() =>
            processor.ProcessAsync(Encode(new Entry("fdo.csr:error", new byte[] { 0x05 }))));

        await Assert.That(error.ErrorCode).IsEqualTo(5UL);
        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCaCertificates())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task RejectsMalformedCaMaterialWithoutPreparingEnrollment()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue, requestCaCertificates: true);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();
        Entry invalid = TextEntry("fdo.csr:cacerts-res", Convert.ToBase64String(new byte[] { 0x30, 0x00 }));

        await CatchAsync<CryptographicException>(() => processor.ProcessAsync(Encode(invalid)));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCaCertificates())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.MarkRequestSent())).IsTrue();
    }

    [Test]
    public async Task RejectsAResponseBeforeOwnerActivation()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        Entry response = new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeResponse(
            fixture.Request, fixture.Certificate);

        await CatchAsync<CborContentException>(() => processor.ProcessAsync(Encode(response)));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task RejectsAResponseInTheActivationMessageBeforeTheRequestIsSent()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        Entry response = new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeResponse(
            fixture.Request, fixture.Certificate);

        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF5 }), response)));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.MarkRequestSent())).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task RejectsACertificateForAnotherKeyAndDoesNotRetry()
    {
        using var fixture = new Fixture();
        using var other = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();
        Entry wrongResponse = TextEntry("fdo.csr:simpleenroll-res", Convert.ToBase64String(other.Certificate));

        await CatchAsync<CryptographicException>(() => processor.ProcessAsync(Encode(wrongResponse)));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
        Entry correct = new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeResponse(
            fixture.Request, fixture.Certificate);
        await CatchAsync<InvalidOperationException>(() => processor.ProcessAsync(Encode(correct)));
    }

    [Test]
    public async Task ReportsAnOwnerModuleErrorAndFaultsTheExchange()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        FdoCsrModuleException error = await CatchAsync<FdoCsrModuleException>(() =>
            processor.ProcessAsync(Encode(new Entry("fdo.csr:error", new byte[] { 0x02 }))));

        await Assert.That(error.ErrorCode).IsEqualTo(2UL);
        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    [Test]
    public async Task DisablingAnAwaitingModuleDoesNotProduceACertificate()
    {
        using var fixture = new Fixture();
        var module = new FdoCsrDeviceModule(fixture.Request, ushort.MaxValue);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        IReadOnlyList<Entry> outgoing = Decode(await processor.ProcessAsync(Encode(
            new Entry("fdo.csr:active", new byte[] { 0xF4 }))));

        await Assert.That(outgoing.Count).IsEqualTo(0);
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
        Entry response = new FdoCsrBase64TextCodec(ushort.MaxValue).EncodeResponse(
            fixture.Request, fixture.Certificate);
        await CatchAsync<CborContentException>(() => processor.ProcessAsync(Encode(response)));
        await Assert.That(processor.IsFaulted).IsTrue();
    }

    [Test]
    public async Task RejectsAnOversizedCertificateInsteadOfFragmentingIt()
    {
        using var fixture = new Fixture();
        var codec = new FdoCsrBase64TextCodec(ushort.MaxValue);
        Entry request = codec.EncodeRequest(fixture.Request);
        Entry response = codec.EncodeResponse(fixture.Request, fixture.Certificate);
        var to2 = new FdoTo2ServiceInfoCodec();
        int requestLimit = to2.EncodeDevice(false, [request]).Length;
        int responseLength = to2.EncodeDevice(false, [response]).Length;
        await Assert.That(responseLength > requestLimit).IsTrue();
        var module = new FdoCsrDeviceModule(fixture.Request, requestLimit);
        var processor = new FdoDeviceServiceInfoProcessor([module]);
        await processor.ProcessAsync(Encode(new Entry("fdo.csr:active", new byte[] { 0xF5 })));
        module.MarkRequestSent();

        await CatchAsync<CborContentException>(() => processor.ProcessAsync(Encode(response)));

        await Assert.That(processor.IsFaulted).IsTrue();
        await Assert.That(Throws<InvalidOperationException>(() => module.CopyPendingCertificate())).IsTrue();
    }

    private static Entry TextEntry(string key, string value)
    {
        var writer = new CborWriter(CborConformanceMode.Canonical);
        writer.WriteTextString(value);
        return new Entry(key, writer.Encode());
    }

    private static ReadOnlyMemory<byte> Encode(params Entry[] entries) =>
        new FdoServiceInfoCodec().Encode(entries);

    private static IReadOnlyList<Entry> Decode(ReadOnlyMemory<byte> encoded) =>
        new FdoServiceInfoCodec().Decode(encoded);

    private static async Task<TException> CatchAsync<TException>(Func<Task<ReadOnlyMemory<byte>>> action)
        where TException : Exception
    {
        try
        {
            await action();
        }
        catch (TException exception)
        {
            return exception;
        }

        throw new InvalidOperationException($"Expected {typeof(TException).Name}.");
    }

    private static bool Throws<TException>(Action action)
        where TException : Exception
    {
        try
        {
            action();
            return false;
        }
        catch (TException)
        {
            return true;
        }
    }

    private static void ClearExposedMemory(ReadOnlyMemory<byte> value)
    {
        if (!MemoryMarshal.TryGetArray(value, out ArraySegment<byte> segment) || segment.Array is null)
        {
            throw new InvalidOperationException("The test expected array-backed memory.");
        }

        Array.Clear(segment.Array, segment.Offset, segment.Count);
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly X509Certificate2 _certificate;

        public Fixture()
        {
            var request = new CertificateRequest("CN=FDO test Device", _key, HashAlgorithmName.SHA256);
            Request = request.CreateSigningRequest();
            var names = new SubjectAlternativeNameBuilder();
            for (int i = 0; i < 20; i++)
            {
                names.AddDnsName($"device-{i}.example.invalid");
            }

            request.CertificateExtensions.Add(names.Build());
            _certificate = request.CreateSelfSigned(
                DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
            Certificate = _certificate.RawData;
        }

        public byte[] Request { get; }
        public byte[] Certificate { get; }

        public void Dispose()
        {
            _certificate.Dispose();
            _key.Dispose();
        }
    }
}
