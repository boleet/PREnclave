using BenchmarkDotNet.Running;
using PREnclaveTester;
using TesterPREnclaveSGX;

FunctionalTests functionalTests = new FunctionalTests(true);
functionalTests.TestAll();


//var summary = BenchmarkRunner.Run<BenchmarkTEE>();
//var summary2 = BenchmarkRunner.Run<BenchmarkCsharp>();

Console.WriteLine("Done");
