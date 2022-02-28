from fastapi import FastAPI, File, UploadFile
from starlette.responses import RedirectResponse
import pandas as pd
import itertools
import pefile
import os
import tempfile
import unidecode
# creating fastApi app
app = FastAPI()

pathDataCsv = "PeDumpData.csv"


def createDataframeFromPEdump(nameFile, pe, malware: bool):

    dosHeaders = ['e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr',
                  'e_minalloc', 'e_maxalloc', 'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs',
                  'e_lfarlc', 'e_ovno', 'e_oemid', 'e_oeminfo', 'e_lfanew']
    fileHeaders = ['Machine',
                   'NumberOfSections', 'TimeDateStamp', 'PointerToSymbolTable',
                   'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics']
    optionalHeaders = ['Magic',
                       'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode',
                       'SizeOfInitializedData', 'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode',
                       'ImageBase', 'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
                       'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
                       'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders',
                       'CheckSum', 'SizeOfImage', 'Subsystem', 'DllCharacteristics',
                       'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
                       'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes']
    imageDirectory = ['ImageDirectoryEntryExport', 'ImageDirectoryEntryImport',
                      'ImageDirectoryEntryResource', 'ImageDirectoryEntryException',
                      'ImageDirectoryEntrySecurity']

    dheaders = {}
    fheaders = {}
    oheaders = {}
    imd1 = {}

    df = pd.DataFrame({"Name": nameFile}, index=[0])

    for x in dosHeaders:
        dheaders[x] = getattr(pe.DOS_HEADER, x)
    df = pd.concat([df, pd.DataFrame(dheaders, index=[0])], axis=1)
    # df = pd.DataFrame(dheaders, index=[0])

    for i in fileHeaders:
        fheaders[i] = getattr(pe.FILE_HEADER, i)
    df = pd.concat([df, (pd.DataFrame(fheaders, index=[0]))], axis=1)

    for y in optionalHeaders:
        oheaders[y] = getattr(pe.OPTIONAL_HEADER, y)
    df = pd.concat([df, (pd.DataFrame(oheaders, index=[0]))], axis=1)

    for q in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        imd1[q.name] = q.VirtualAddress
    imd1 = dict(itertools.islice(imd1.items(), 5))
    df = pd.concat([df, (pd.DataFrame(imd1, index=[0]))], axis=1)
    malware = {'Malware': int(malware)}
    df = pd.concat([df, (pd.DataFrame(malware, index=[0]))], axis=1)
    return df


@app.get("/")
async def index():
    return {"message": "Hello World"}
    # return RedirectResponse(url="/docs")


@app.post("/createData")
def parse(file: UploadFile = File(...), malware: bool = False):
    extension = os.path.splitext(file.filename)[1]
    _, path = tempfile.mkstemp(prefix='parser_', suffix=extension)
    nameFile = unidecode.unidecode(file.filename).replace(" ", "_")
    with open(path, 'ab') as f:
        for chunk in iter(lambda: file.file.read(10000), b''):
            f.write(chunk)

    # extract content
    content = pefile.PE(path, fast_load=True)
    dataframe = createDataframeFromPEdump(nameFile, content, malware)
    # if os.path.isfile(pathDataCsv):
    #     dataframe.to_csv(pathDataCsv, mode='a', index=False, header=False)
    # else:
    #     dataframe.to_csv(pathDataCsv, mode='a', index=False, header=True)
    print(dataframe)
    return dataframe.to_dict(orient="index")
    os.close(_)
    os.remove(path)
