
import { getUrl, ExtractorConfig, getStreamContent } from '../src/extractor';
import * as dotenv from 'dotenv';
dotenv.config();

const config: ExtractorConfig = {
    vixDirect: true,
    vixProxy: false
};

const TMDB_ID = 'tmdb:1589891';
const TYPE = 'movie';

async function run() {
    console.log(`Testing resolution for ${TMDB_ID} (${TYPE})...`);
    try {
        const url = await getUrl(TMDB_ID, TYPE, config);
        console.log('Generated URL:', url);

        if (url) {
            console.log('Fetching content...');
            const streams = await getStreamContent(TMDB_ID, TYPE, config);
            console.log('Streams found:', streams ? streams.length : 0);
            if (streams) console.log(JSON.stringify(streams, null, 2));
        } else {
            console.log('URL generation failed (returned null).');
        }

    } catch (e) {
        console.error('Error:', e);
    }
}

run();
