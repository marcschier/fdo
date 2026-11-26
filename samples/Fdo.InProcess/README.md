# Initialize a Device in process

The Device and Manufacturer use an `IFdoDeviceInitializeTransport` that calls
the Manufacturer directly. The example installs a staged Device credential,
then transfers the persisted voucher to a new Owner.

From the repository root, run:

```powershell
dotnet run --project samples/Fdo.InProcess --framework net10.0
```

Look for `FDO initialization complete; transferred voucher has one Owner entry.`
Use `--framework net11.0` to run on .NET 11. The sample uses ephemeral keys and
in-memory state; do not use its reservation and storage callbacks for production.
