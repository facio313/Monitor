import { createServer } from 'node:http';
import { createApp } from './app.js';

const portValue = Number(process.env.PORT ?? 8080);
const port = Number.isInteger(portValue) && portValue > 0 && portValue <= 65_535 ? portValue : 8080;
const host = process.env.HOST ?? '0.0.0.0';
const server = createServer(createApp());

server.listen(port, host, () => {
  process.stdout.write(`Monitor server listening on ${host}:${port}\n`);
});

function shutdown(signal: string): void {
  process.stdout.write(`Monitor server received ${signal}; shutting down\n`);
  server.close((error) => {
    if (error) {
      process.stderr.write('Monitor server failed to shut down cleanly\n');
      process.exitCode = 1;
    }
  });
  setTimeout(() => {
    process.stderr.write('Monitor server shutdown timed out\n');
    process.exit(1);
  }, 10_000).unref();
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));

export { createApp } from './app.js';
