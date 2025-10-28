from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timedelta
import httpx
import base64
import json
from fastapi.responses import JSONResponse


from dotenv import load_dotenv
load_dotenv()
    
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# Configuration de l'authentification
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Variables d'environnement pour l'authentification
APP_USERNAME = os.environ.get("APP_USERNAME", "admin")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "password")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 480))

# Modèles d'authentification
class LoginRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Fonctions d'authentification
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifier un mot de passe"""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hasher un mot de passe"""
    return pwd_context.hash(password)

def authenticate_user(username: str, password: str) -> bool:
    """Authentifier un utilisateur"""
    if username != APP_USERNAME:
        return False
    if password != APP_PASSWORD:
        return False
    return True

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Créer un token JWT"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Vérifier le token JWT et retourner l'utilisateur actuel"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    if token_data.username != APP_USERNAME:
        raise credentials_exception
    return token_data.username

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI(title="D&B Business Partner Search API", version="1.0.0")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Token cache for D&B API
token_cache = {"token": "", "expiry": datetime.now()}

# D&B API Base URL
DNB_API_BASE = "https://plus.dnb.com"

# Define Complete Models from D&B JSON Examples
class TransactionDetail(BaseModel):
    transactionID: Optional[str] = None
    transactionTimestamp: Optional[str] = None
    inLanguage: Optional[str] = None

class InquiryDetail(BaseModel):
    duns: Optional[str] = None
    blockIDs: Optional[List[str]] = None

class PrimaryIndustryCode(BaseModel):
    usSicV4: Optional[str] = None
    usSicV4Description: Optional[str] = None

class TelephoneInfo(BaseModel):
    telephoneNumber: Optional[str] = None
    isdCode: Optional[str] = None

class OperatingStatus(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class OperatingSubStatus(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None
    startDate: Optional[str] = None

class DetailedOperatingStatus(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class SubjectHandlingDetail(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class DunsControlStatus(BaseModel):
    operatingStatus: Optional[OperatingStatus] = None
    isMarketable: Optional[bool] = None
    isMailUndeliverable: Optional[bool] = None
    isTelephoneDisconnected: Optional[bool] = None
    isDelisted: Optional[bool] = None
    subjectHandlingDetails: Optional[List[SubjectHandlingDetail]] = None
    firstReportDate: Optional[str] = None
    operatingSubStatus: Optional[OperatingSubStatus] = None
    detailedOperatingStatus: Optional[DetailedOperatingStatus] = None

class TradeStyleName(BaseModel):
    name: Optional[str] = None
    priority: Optional[int] = None

class Language(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class WritingScript(BaseModel):
    pass  # Can be empty object

class AddressCountry(BaseModel):
    name: Optional[str] = None
    isoAlpha2Code: Optional[str] = None

class ContinentalRegion(BaseModel):
    name: Optional[str] = None

class AddressLocality(BaseModel):
    name: Optional[str] = None

class AddressRegion(BaseModel):
    name: Optional[str] = None
    abbreviatedName: Optional[str] = None
    isoSubDivisionName: Optional[str] = None
    isoSubDivisionCode: Optional[str] = None

class AddressCounty(BaseModel):
    name: Optional[str] = None

class PostalCodePosition(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class StreetAddress(BaseModel):
    line1: Optional[str] = None
    line2: Optional[str] = None

class PostOfficeBox(BaseModel):
    pass  # Can be empty

class StandardAddressCode(BaseModel):
    pass  # Array of objects

class PrimaryAddress(BaseModel):
    language: Optional[Language] = None
    addressCountry: Optional[AddressCountry] = None
    continentalRegion: Optional[ContinentalRegion] = None
    addressLocality: Optional[AddressLocality] = None
    minorTownName: Optional[str] = None
    addressRegion: Optional[AddressRegion] = None
    addressCounty: Optional[AddressCounty] = None
    postalCode: Optional[str] = None
    postalCodePosition: Optional[PostalCodePosition] = None
    streetNumber: Optional[str] = None
    streetName: Optional[str] = None
    streetAddress: Optional[StreetAddress] = None
    postOfficeBox: Optional[PostOfficeBox] = None
    standardAddressCodes: Optional[List[StandardAddressCode]] = None
    isRegisteredAddress: Optional[bool] = None

class MultilingualAddress(BaseModel):
    language: Optional[Language] = None
    writingScript: Optional[WritingScript] = None
    addressCountry: Optional[AddressCountry] = None
    continentalRegion: Optional[ContinentalRegion] = None
    addressLocality: Optional[AddressLocality] = None
    minorTownName: Optional[str] = None
    addressRegion: Optional[AddressRegion] = None
    addressCounty: Optional[AddressCounty] = None
    postalCode: Optional[str] = None
    streetNumber: Optional[str] = None
    streetName: Optional[str] = None
    streetAddress: Optional[StreetAddress] = None

class Activity(BaseModel):
    description: Optional[str] = None
    language: Optional[Language] = None

class RegistrationNumberClass(BaseModel):
    description: Optional[str] = None
    dnbCode: Optional[int] = None

class RegistrationNumber(BaseModel):
    registrationNumber: Optional[str] = None
    typeDescription: Optional[str] = None
    typeDnBCode: Optional[int] = None
    registrationNumberClass: Optional[RegistrationNumberClass] = None
    isPreferredRegistrationNumber: Optional[bool] = None
    registrationLocation: Optional[str] = None

class EmailAddress(BaseModel):
    address: Optional[str] = None

class UnspscCode(BaseModel):
    code: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None

class MultilingualName(BaseModel):
    language: Optional[Language] = None
    name: Optional[str] = None
    writingScript: Optional[WritingScript] = None

class WebsiteAddress(BaseModel):
    url: Optional[str] = None
    domainName: Optional[str] = None

class StockExchange(BaseModel):
    name: Optional[str] = None

class BlockStatus(BaseModel):
    blockID: Optional[str] = None
    status: Optional[str] = None
    reason: Optional[str] = None

class CompleteOrganization(BaseModel):
    duns: Optional[str] = None
    isNonClassifiedEstablishment: Optional[bool] = None
    primaryIndustryCode: Optional[PrimaryIndustryCode] = None
    primaryName: Optional[str] = None
    certifiedEmail: Optional[str] = None
    telephone: Optional[List[TelephoneInfo]] = None
    dunsControlStatus: Optional[DunsControlStatus] = None
    tradeStyleNames: Optional[List[TradeStyleName]] = None
    multiLingualSearchNames: Optional[List[Any]] = None
    multilingualPrimaryAddress: Optional[List[MultilingualAddress]] = None
    countryISOAlpha2Code: Optional[str] = None
    primaryAddress: Optional[PrimaryAddress] = None
    securitiesReportID: Optional[str] = None
    activities: Optional[List[Activity]] = None
    defaultCurrency: Optional[str] = None
    registrationNumbers: Optional[List[RegistrationNumber]] = None
    email: Optional[List[EmailAddress]] = None
    unspscCodes: Optional[List[UnspscCode]] = None
    multilingualPrimaryName: Optional[List[MultilingualName]] = None
    multilingualRegisteredNames: Optional[List[MultilingualName]] = None
    multilingualTradestyleNames: Optional[List[MultilingualName]] = None
    preferredLanguage: Optional[Language] = None
    legalEntityIdentifier: Optional[str] = None
    stockExchanges: Optional[List[StockExchange]] = None
    websiteAddress: Optional[List[WebsiteAddress]] = None
    standardizedStockExchanges: Optional[List[Any]] = None

class CompleteDnBResponse(BaseModel):
    transactionDetail: Optional[TransactionDetail] = None
    inquiryDetail: Optional[InquiryDetail] = None
    organization: Optional[CompleteOrganization] = None
    blockStatus: Optional[List[BlockStatus]] = None

class UnifiedSearchRequest(BaseModel):
    """Modèle de recherche unifié basé sur le GRS (Global Reference Solution) de D&B"""
    
    # === IDENTIFICATION ===
    duns: Optional[str] = None                      # Numéro D-U-N-S®
    local_identifier: Optional[str] = None          # Identifiant local (SIRET, EIN, etc.)
    company_name: Optional[str] = None              # Raison sociale
    
    # === ADRESSE ===
    address: Optional[str] = None                   # Adresse
    city: Optional[str] = None                      # Ville
    postal_code: Optional[str] = None               # Code postal
    state: Optional[str] = None                     # État
    country: Optional[str] = None                   # Pays/Région
    continent: Optional[str] = None                 # Continent
    
    # === CONTACT ===
    phone_fax: Optional[str] = None                 # Téléphone/Fax
    has_phone: Optional[bool] = None                # Téléphone présent
    has_fax: Optional[bool] = None                  # Fax présent
    
    # === COMPATIBILITÉ ANCIENNES VERSIONS ===
    street_address: Optional[str] = None
    national_id: Optional[str] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    email: Optional[str] = None
    industry: Optional[str] = None
    business_type: Optional[str] = None
    employee_count_min: Optional[int] = None
    employee_count_max: Optional[int] = None
    annual_revenue_min: Optional[str] = None
    annual_revenue_max: Optional[str] = None
    year_started_min: Optional[int] = None
    year_started_max: Optional[int] = None
    operating_status: Optional[str] = None
    legal_name: Optional[str] = None
    trade_name: Optional[str] = None
    stock_exchange: Optional[str] = None

    @field_validator('duns')
    @classmethod
    def validate_duns(cls, v):
        if v:
            # Remove any spaces or dashes
            cleaned = v.replace(' ', '').replace('-', '')
            if not cleaned.isdigit():
                raise ValueError("DUNS number must contain only digits")
            if len(cleaned) not in [9, 10]:
                raise ValueError("DUNS number must be 9 or 10 digits")
            return cleaned
        return v
    
    @field_validator('local_identifier', 'national_id')
    @classmethod  
    def validate_identifiers(cls, v):
        if v:
            return v.strip()
        return v

class DUNSRequest(BaseModel):
    duns: str
    
    @field_validator('duns')
    @classmethod
    def validate_duns(cls, v):
        # Remove any spaces or dashes
        cleaned = v.replace(' ', '').replace('-', '')
        if not cleaned.isdigit():
            raise ValueError("DUNS number must contain only digits")
        if len(cleaned) != 9:
            raise ValueError("DUNS number must be exactly 9 digits")
        return cleaned

class CompanySearchRequest(BaseModel):
    name: str
    country: Optional[str] = None

class HierarchyOrganization(BaseModel):
    duns: Optional[str] = None
    primaryName: Optional[str] = None
    isStandalone: Optional[bool] = None
    
class FamilyTreeMember(BaseModel):
    duns: Optional[str] = None
    primaryName: Optional[str] = None
    relationshipCode: Optional[str] = None
    relationshipDescription: Optional[str] = None
    isStandalone: Optional[bool] = None
    hierarchyLevel: Optional[int] = None
    
class CorporateHierarchy(BaseModel):
    familyTreeMembersCount: Optional[int] = None
    familyTreeMembers: Optional[List[FamilyTreeMember]] = None
    hierarchyLevel: Optional[int] = None
    globalUltimate: Optional[HierarchyOrganization] = None
    domesticUltimate: Optional[HierarchyOrganization] = None
    parent: Optional[HierarchyOrganization] = None
    subsidiaries: Optional[List[HierarchyOrganization]] = None

class ExtendedBusinessPartnerInfo(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    
    # Transaction et Inquiry Details
    transaction_detail: Optional[TransactionDetail] = None
    inquiry_detail: Optional[InquiryDetail] = None
    
    # Organization Complete - Tous les champs D&B
    duns: str
    is_non_classified_establishment: Optional[bool] = None
    primary_industry_code: Optional[PrimaryIndustryCode] = None
    primary_name: Optional[str] = None
    certified_email: Optional[str] = None
    telephone: Optional[List[TelephoneInfo]] = None
    duns_control_status: Optional[DunsControlStatus] = None
    trade_style_names: Optional[List[TradeStyleName]] = None
    multi_lingual_search_names: Optional[List[Any]] = None
    multilingual_primary_address: Optional[List[MultilingualAddress]] = None
    country_iso_alpha2_code: Optional[str] = None
    primary_address: Optional[PrimaryAddress] = None
    securities_report_id: Optional[str] = None
    activities: Optional[List[Activity]] = None
    default_currency: Optional[str] = None
    registration_numbers: Optional[List[RegistrationNumber]] = None
    email: Optional[List[EmailAddress]] = None
    unspsc_codes: Optional[List[UnspscCode]] = None
    multilingual_primary_name: Optional[List[MultilingualName]] = None
    multilingual_registered_names: Optional[List[MultilingualName]] = None
    multilingual_tradestyle_names: Optional[List[MultilingualName]] = None
    preferred_language: Optional[Language] = None
    legal_entity_identifier: Optional[str] = None
    stock_exchanges: Optional[List[StockExchange]] = None
    website_address: Optional[List[WebsiteAddress]] = None
    standardized_stock_exchanges: Optional[List[Any]] = None
    
    # Block Status
    block_status: Optional[List[BlockStatus]] = None
    
    # Corporate Hierarchy Information
    corporate_hierarchy: Optional[CorporateHierarchy] = None
    
    # Ranking Info (pour compatibilité)
    match_grade: Optional[int] = None
    confidence_code: Optional[int] = None
    ranking_info: Optional[Dict[str, Any]] = None
    
    # Méta-données
    search_criteria: Optional[Dict[str, Any]] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    data_source: Optional[str] = "D&B API Company Info L1"

class BusinessPartnerInfo(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    duns: str
    company_name: str
    legal_name: Optional[str] = None
    address: Optional[Dict[str, Any]] = None
    phone: Optional[str] = None
    website: Optional[str] = None
    industry: Optional[str] = None
    employee_count: Optional[int] = None
    annual_revenue: Optional[str] = None
    risk_rating: Optional[str] = None
    business_type: Optional[str] = None
    year_started: Optional[int] = None
    status: Optional[str] = None
    search_criteria: Optional[Dict[str, Any]] = None
    last_updated: datetime = Field(default_factory=datetime.utcnow)

class SearchResult(BaseModel):
    results: List[Dict[str, Any]]
    total_count: int
    search_query: str
    search_criteria: Dict[str, Any]

# D&B API Integration Functions
async def get_corporate_hierarchy(duns: str) -> Optional[CorporateHierarchy]:
    """Récupère les informations de hiérarchie corporate depuis l'API D&B"""
    try:
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        logger.info(f"Fetching corporate hierarchy for DUNS: {duns}")
        
        # Essayer l'API Hierarchy and Connections L1
        async with httpx.AsyncClient(timeout=30.0) as client:
            # URL pour l'API Hierarchy and Connections
            hierarchy_url = f"{DNB_API_BASE}/v1/data/duns/{duns}?blockIDs=hierarchyconnections_L1_v1"
            
            response = await client.get(hierarchy_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully retrieved hierarchy data for DUNS: {duns}")
                
                # Parser les données de hiérarchie
                return parse_hierarchy_data(data, duns)
            elif response.status_code == 404:
                logger.info(f"No hierarchy data found for DUNS: {duns}")
                return None
            else:
                logger.warning(f"Hierarchy API returned {response.status_code}: {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error fetching corporate hierarchy for DUNS {duns}: {str(e)}")
        return None

async def get_family_tree(duns: str) -> Optional[List[FamilyTreeMember]]:
    """Récupère l'arbre familial complet depuis l'API D&B"""
    try:
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        logger.info(f"Fetching family tree for DUNS: {duns}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # URL pour l'API Corporate Family Tree
            family_tree_url = f"{DNB_API_BASE}/v1/familytree/{duns}?hierarchyDirection=upward"
            
            response = await client.get(family_tree_url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"Successfully retrieved family tree data for DUNS: {duns}")
                
                # Parser les données de l'arbre familial
                return parse_family_tree_data(data)
            elif response.status_code == 404:
                logger.info(f"No family tree data found for DUNS: {duns}")
                return None
            else:
                logger.warning(f"Family Tree API returned {response.status_code}: {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error fetching family tree for DUNS {duns}: {str(e)}")
        return None

def parse_hierarchy_data(data: Dict[str, Any], duns: str) -> Optional[CorporateHierarchy]:
    """Parse les données de hiérarchie de l'API D&B"""
    try:
        logger.info(f"Parsing hierarchy data for DUNS: {duns}")
        
        organization = data.get("organization", {})
        
        # Rechercher les informations de hiérarchie dans différents blocks
        hierarchy_info = None
        
        # Chercher dans les différents blocks possibles
        if "corporateLinkage" in organization:
            hierarchy_info = organization["corporateLinkage"]
        elif "hierarchyConnections" in organization:
            hierarchy_info = organization["hierarchyConnections"]
        
        if not hierarchy_info:
            logger.info(f"No hierarchy information found in response for DUNS: {duns}")
            return None
        
        # Parser les informations de base
        corporate_hierarchy = CorporateHierarchy()
        
        # Global Ultimate
        if "globalUltimate" in hierarchy_info:
            gu = hierarchy_info["globalUltimate"]
            corporate_hierarchy.globalUltimate = HierarchyOrganization(
                duns=gu.get("duns"),
                primaryName=gu.get("primaryName"),
                isStandalone=gu.get("isStandalone")
            )
        
        # Domestic Ultimate
        if "domesticUltimate" in hierarchy_info:
            du = hierarchy_info["domesticUltimate"]
            corporate_hierarchy.domesticUltimate = HierarchyOrganization(
                duns=du.get("duns"),
                primaryName=du.get("primaryName"),
                isStandalone=du.get("isStandalone")
            )
        
        # Parent
        if "parent" in hierarchy_info:
            parent = hierarchy_info["parent"]
            corporate_hierarchy.parent = HierarchyOrganization(
                duns=parent.get("duns"),
                primaryName=parent.get("primaryName"),
                isStandalone=parent.get("isStandalone")
            )
        
        # Subsidiaries
        if "subsidiaries" in hierarchy_info:
            subsidiaries = []
            for sub in hierarchy_info["subsidiaries"]:
                subsidiaries.append(HierarchyOrganization(
                    duns=sub.get("duns"),
                    primaryName=sub.get("primaryName"),
                    isStandalone=sub.get("isStandalone")
                ))
            corporate_hierarchy.subsidiaries = subsidiaries
        
        # Hierarchy level
        corporate_hierarchy.hierarchyLevel = hierarchy_info.get("hierarchyLevel", 0)
        
        logger.info(f"Successfully parsed hierarchy data for DUNS: {duns}")
        return corporate_hierarchy
        
    except Exception as e:
        logger.error(f"Error parsing hierarchy data for DUNS {duns}: {str(e)}")
        return None

def parse_family_tree_data(data: Dict[str, Any]) -> Optional[List[FamilyTreeMember]]:
    """Parse les données de l'arbre familial de l'API D&B"""
    try:
        logger.info("Parsing family tree data")
        
        family_tree_members = []
        
        # Récupérer les membres de l'arbre familial
        if "familyTreeMembers" in data:
            for member in data["familyTreeMembers"]:
                family_tree_member = FamilyTreeMember(
                    duns=member.get("duns"),
                    primaryName=member.get("primaryName"),
                    relationshipCode=member.get("relationshipCode"),
                    relationshipDescription=member.get("relationshipDescription"),
                    isStandalone=member.get("isStandalone"),
                    hierarchyLevel=member.get("hierarchyLevel")
                )
                family_tree_members.append(family_tree_member)
        
        logger.info(f"Successfully parsed {len(family_tree_members)} family tree members")
        return family_tree_members if family_tree_members else None
        
    except Exception as e:
        logger.error(f"Error parsing family tree data: {str(e)}")
        return None

async def get_duns_token():
    """Get access token from D&B API"""
    try:
        consumer_key = os.getenv('DUNS_CONSUMER_KEY')
        consumer_secret = os.getenv('DUNS_CONSUMER_SECRET')
        
        if not consumer_key or not consumer_secret:
            raise HTTPException(status_code=500, detail="D&B API credentials not configured")
            
        auth_string = f"{consumer_key}:{consumer_secret}"
        encoded_credentials = base64.b64encode(auth_string.encode()).decode()
        
        headers = {
            "Authorization": f"Basic {encoded_credentials}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{DNB_API_BASE}/v3/token",
                headers=headers,
                data="grant_type=client_credentials"
            )
            
            if response.status_code != 200:
                logger.error(f"D&B authentication failed: {response.status_code} - {response.text}")
                raise HTTPException(status_code=401, detail="D&B authentication failed")
                
            token_data = response.json()
            return token_data["access_token"]
            
    except httpx.RequestError as e:
        logger.error(f"D&B API connection error: {str(e)}")
        raise HTTPException(status_code=503, detail="Unable to connect to D&B API")
    except Exception as e:
        logger.error(f"Error getting D&B token: {str(e)}")
        raise HTTPException(status_code=500, detail="Authentication error")

async def get_cached_token():
    """Get cached token or refresh if expired"""
    if datetime.now() > token_cache["expiry"]:
        token_cache["token"] = await get_duns_token()
        token_cache["expiry"] = datetime.now() + timedelta(hours=1)
    return token_cache["token"]

def parse_complete_dnb_data(data: Dict[str, Any], duns: str, search_criteria: Dict[str, Any] = None) -> ExtendedBusinessPartnerInfo:
    """Parse complete D&B API response with ALL attributes from JSON example"""
    try:
        logger.info(f"=== PARSING COMPLETE D&B DATA ===")
        logger.info(f"Full D&B response data: {json.dumps(data, indent=2, default=str)}")
        
        # Extraire tous les niveaux de la réponse D&B
        transaction_detail = None
        inquiry_detail = None
        organization = None
        block_status = None
        
        if "transactionDetail" in data:
            tx_detail = data["transactionDetail"]
            transaction_detail = TransactionDetail(
                transactionID=tx_detail.get("transactionID"),
                transactionTimestamp=tx_detail.get("transactionTimestamp"),
                inLanguage=tx_detail.get("inLanguage")
            )
        
        if "inquiryDetail" in data:
            inq_detail = data["inquiryDetail"]
            inquiry_detail = InquiryDetail(
                duns=inq_detail.get("duns"),
                blockIDs=inq_detail.get("blockIDs")
            )
        
        if "blockStatus" in data:
            block_status = [BlockStatus(**block) for block in data["blockStatus"]]
        
        # Extraire organization complète
        if "organization" in data:
            org_data = data["organization"]
            
            # Primary Industry Code
            primary_industry = None
            if org_data.get("primaryIndustryCode"):
                pic = org_data["primaryIndustryCode"]
                primary_industry = PrimaryIndustryCode(
                    usSicV4=pic.get("usSicV4"),
                    usSicV4Description=pic.get("usSicV4Description")
                )
            
            # Telephone
            telephone_list = []
            for tel in org_data.get("telephone", []):
                telephone_list.append(TelephoneInfo(
                    telephoneNumber=tel.get("telephoneNumber"),
                    isdCode=tel.get("isdCode")
                ))
            
            # DUNS Control Status
            duns_control = None
            if org_data.get("dunsControlStatus"):
                dcs = org_data["dunsControlStatus"]
                
                operating_status = None
                if dcs.get("operatingStatus"):
                    os_data = dcs["operatingStatus"]
                    operating_status = OperatingStatus(
                        description=os_data.get("description"),
                        dnbCode=os_data.get("dnbCode")
                    )
                
                operating_sub_status = None
                if dcs.get("operatingSubStatus"):
                    oss_data = dcs["operatingSubStatus"]
                    operating_sub_status = OperatingSubStatus(
                        description=oss_data.get("description"),
                        dnbCode=oss_data.get("dnbCode"),
                        startDate=oss_data.get("startDate")
                    )
                
                detailed_operating_status = None
                if dcs.get("detailedOperatingStatus"):
                    dos_data = dcs["detailedOperatingStatus"]
                    detailed_operating_status = DetailedOperatingStatus(
                        description=dos_data.get("description"),
                        dnbCode=dos_data.get("dnbCode")
                    )
                
                duns_control = DunsControlStatus(
                    operatingStatus=operating_status,
                    isMarketable=dcs.get("isMarketable"),
                    isMailUndeliverable=dcs.get("isMailUndeliverable"),
                    isTelephoneDisconnected=dcs.get("isTelephoneDisconnected"),
                    isDelisted=dcs.get("isDelisted"),
                    subjectHandlingDetails=[SubjectHandlingDetail(
                        description=detail.get("description"),
                        dnbCode=detail.get("dnbCode")
                    ) for detail in dcs.get("subjectHandlingDetails", [])],
                    firstReportDate=dcs.get("firstReportDate"),
                    operatingSubStatus=operating_sub_status,
                    detailedOperatingStatus=detailed_operating_status
                )
            
            # Trade Style Names
            trade_styles = []
            for ts in org_data.get("tradeStyleNames", []):
                trade_styles.append(TradeStyleName(
                    name=ts.get("name"),
                    priority=ts.get("priority")
                ))
            
            # Primary Address
            primary_addr = None
            if org_data.get("primaryAddress"):
                pa = org_data["primaryAddress"]
                
                language = None
                if pa.get("language"):
                    lang = pa["language"]
                    language = Language(
                        description=lang.get("description"),
                        dnbCode=lang.get("dnbCode")
                    )
                
                address_country = None
                if pa.get("addressCountry"):
                    ac = pa["addressCountry"]
                    address_country = AddressCountry(
                        name=ac.get("name"),
                        isoAlpha2Code=ac.get("isoAlpha2Code")
                    )
                
                continental_region = None
                if pa.get("continentalRegion"):
                    cr = pa["continentalRegion"]
                    continental_region = ContinentalRegion(name=cr.get("name"))
                
                address_locality = None
                if pa.get("addressLocality"):
                    al = pa["addressLocality"]
                    address_locality = AddressLocality(name=al.get("name"))
                
                address_region = None
                if pa.get("addressRegion"):
                    ar = pa["addressRegion"]
                    address_region = AddressRegion(
                        name=ar.get("name"),
                        abbreviatedName=ar.get("abbreviatedName"),
                        isoSubDivisionName=ar.get("isoSubDivisionName"),
                        isoSubDivisionCode=ar.get("isoSubDivisionCode")
                    )
                
                address_county = None
                if pa.get("addressCounty"):
                    aco = pa["addressCounty"]
                    address_county = AddressCounty(name=aco.get("name"))
                
                postal_code_position = None
                if pa.get("postalCodePosition"):
                    pcp = pa["postalCodePosition"]
                    postal_code_position = PostalCodePosition(
                        description=pcp.get("description"),
                        dnbCode=pcp.get("dnbCode")
                    )
                
                street_address = None
                if pa.get("streetAddress"):
                    sa = pa["streetAddress"]
                    street_address = StreetAddress(
                        line1=sa.get("line1"),
                        line2=sa.get("line2")
                    )
                
                primary_addr = PrimaryAddress(
                    language=language,
                    addressCountry=address_country,
                    continentalRegion=continental_region,
                    addressLocality=address_locality,
                    minorTownName=pa.get("minorTownName"),
                    addressRegion=address_region,
                    addressCounty=address_county,
                    postalCode=pa.get("postalCode"),
                    postalCodePosition=postal_code_position,
                    streetNumber=pa.get("streetNumber"),
                    streetName=pa.get("streetName"),
                    streetAddress=street_address,
                    postOfficeBox=PostOfficeBox(),
                    standardAddressCodes=[],
                    isRegisteredAddress=pa.get("isRegisteredAddress")
                )
            
            # Activities
            activities_list = []
            for act in org_data.get("activities", []):
                lang = None
                if act.get("language"):
                    l = act["language"]
                    lang = Language(description=l.get("description"), dnbCode=l.get("dnbCode"))
                activities_list.append(Activity(
                    description=act.get("description"),
                    language=lang
                ))
            
            # Registration Numbers
            reg_numbers = []
            for rn in org_data.get("registrationNumbers", []):
                reg_class = None
                if rn.get("registrationNumberClass"):
                    rnc = rn["registrationNumberClass"]
                    reg_class = RegistrationNumberClass(
                        description=rnc.get("description"),
                        dnbCode=rnc.get("dnbCode")
                    )
                
                reg_numbers.append(RegistrationNumber(
                    registrationNumber=rn.get("registrationNumber"),
                    typeDescription=rn.get("typeDescription"),
                    typeDnBCode=rn.get("typeDnBCode"),
                    registrationNumberClass=reg_class,
                    isPreferredRegistrationNumber=rn.get("isPreferredRegistrationNumber"),
                    registrationLocation=rn.get("registrationLocation")
                ))
            
            # Email
            email_list = []
            for email in org_data.get("email", []):
                email_list.append(EmailAddress(address=email.get("address")))
            
            # UNSPSC Codes
            unspsc_list = []
            for code in org_data.get("unspscCodes", []):
                unspsc_list.append(UnspscCode(
                    code=code.get("code"),
                    description=code.get("description"),
                    priority=code.get("priority")
                ))
            
            # Multilingual Names
            ml_primary = []
            for name in org_data.get("multilingualPrimaryName", []):
                lang = None
                if name.get("language"):
                    l = name["language"]
                    lang = Language(description=l.get("description"), dnbCode=l.get("dnbCode"))
                ml_primary.append(MultilingualName(
                    language=lang,
                    name=name.get("name"),
                    writingScript=WritingScript()
                ))
            
            # Preferred Language
            pref_lang = None
            if org_data.get("preferredLanguage"):
                pl = org_data["preferredLanguage"]
                pref_lang = Language(
                    description=pl.get("description"),
                    dnbCode=pl.get("dnbCode")
                )
            
            # Stock Exchanges
            stock_ex = []
            for se in org_data.get("stockExchanges", []):
                stock_ex.append(StockExchange(name=se.get("name")))
            
            # Website Address
            websites = []
            for wa in org_data.get("websiteAddress", []):
                websites.append(WebsiteAddress(
                    url=wa.get("url"),
                    domainName=wa.get("domainName")
                ))
            
            # Multilingual Addresses
            ml_addresses = []
            for addr in org_data.get("multilingualPrimaryAddress", []):
                lang = None
                if addr.get("language"):
                    l = addr["language"]
                    lang = Language(description=l.get("description"), dnbCode=l.get("dnbCode"))
                
                addr_country = None
                if addr.get("addressCountry"):
                    ac = addr["addressCountry"]
                    addr_country = AddressCountry(
                        name=ac.get("name"),
                        isoAlpha2Code=ac.get("isoAlpha2Code")
                    )
                
                cont_region = None
                if addr.get("continentalRegion"):
                    cr = addr["continentalRegion"]
                    cont_region = ContinentalRegion(name=cr.get("name"))
                
                addr_locality = None
                if addr.get("addressLocality"):
                    al = addr["addressLocality"]
                    addr_locality = AddressLocality(name=al.get("name"))
                
                addr_region = None
                if addr.get("addressRegion"):
                    ar = addr["addressRegion"]
                    addr_region = AddressRegion(name=ar.get("name"))
                
                addr_county = None
                if addr.get("addressCounty"):
                    aco = addr["addressCounty"]
                    addr_county = AddressCounty(name=aco.get("name"))
                
                street_addr = None
                if addr.get("streetAddress"):
                    sa = addr["streetAddress"]
                    street_addr = StreetAddress(
                        line1=sa.get("line1"),
                        line2=sa.get("line2")
                    )
                
                ml_addresses.append(MultilingualAddress(
                    language=lang,
                    writingScript=WritingScript(),
                    addressCountry=addr_country,
                    continentalRegion=cont_region,
                    addressLocality=addr_locality,
                    minorTownName=addr.get("minorTownName"),
                    addressRegion=addr_region,
                    addressCounty=addr_county,
                    postalCode=addr.get("postalCode"),
                    streetNumber=addr.get("streetNumber"),
                    streetName=addr.get("streetName"),
                    streetAddress=street_addr
                ))
        
        logger.info(f"Successfully parsed complete D&B data for: {org_data.get('primaryName', 'Unknown')}")
        
        return ExtendedBusinessPartnerInfo(
            # Transaction Details
            transaction_detail=transaction_detail,
            inquiry_detail=inquiry_detail,
            
            # Organization Complete
            duns=duns,
            is_non_classified_establishment=org_data.get("isNonClassifiedEstablishment"),
            primary_industry_code=primary_industry,
            primary_name=org_data.get("primaryName"),
            certified_email=org_data.get("certifiedEmail"),
            telephone=telephone_list if telephone_list else None,
            duns_control_status=duns_control,
            trade_style_names=trade_styles if trade_styles else None,
            multi_lingual_search_names=org_data.get("multiLingualSearchNames"),
            multilingual_primary_address=ml_addresses if ml_addresses else None,
            country_iso_alpha2_code=org_data.get("countryISOAlpha2Code"),
            primary_address=primary_addr,
            securities_report_id=org_data.get("securitiesReportID"),
            activities=activities_list if activities_list else None,
            default_currency=org_data.get("defaultCurrency"),
            registration_numbers=reg_numbers if reg_numbers else None,
            email=email_list if email_list else None,
            unspsc_codes=unspsc_list if unspsc_list else None,
            multilingual_primary_name=ml_primary if ml_primary else None,
            multilingual_registered_names=[],
            multilingual_tradestyle_names=[],
            preferred_language=pref_lang,
            legal_entity_identifier=org_data.get("legalEntityIdentifier"),
            stock_exchanges=stock_ex if stock_ex else None,
            website_address=websites if websites else None,
            standardized_stock_exchanges=org_data.get("standardizedStockExchanges"),
            
            # Block Status
            block_status=block_status,
            
            # Search metadata
            search_criteria=search_criteria,
            data_source="D&B API Company Info L1 (Complete)"
        )
        
    except Exception as e:
        logger.error(f"Error parsing complete D&B data: {str(e)}")
        return ExtendedBusinessPartnerInfo(
            duns=duns,
            primary_name="Error parsing data",
            search_criteria=search_criteria
        )

def get_confidence_description(confidence_code: int) -> str:
    """Retourne la description du code de confiance D&B"""
    if confidence_code >= 9:
        return "Correspondance excellente"
    elif confidence_code >= 8:
        return "Correspondance très bonne"
    elif confidence_code >= 6:
        return "Correspondance bonne"
    elif confidence_code >= 4:
        return "Correspondance acceptable"
    else:
        return "Correspondance faible"

def get_match_quality(match_grade: int) -> str:
    """Retourne la qualité de correspondance selon le grade"""
    if match_grade >= 9:
        return "Excellente"
    elif match_grade >= 7:
        return "Très bonne"
    elif match_grade >= 5:
        return "Bonne"
    elif match_grade >= 3:
        return "Acceptable"
    else:
        return "Faible"

def get_country_iso_code(country_name: str) -> str:
    """Convertit le nom du pays en code ISO Alpha-2 pour l'API D&B GRS"""
    country_codes = {
        # Europe
        "France": "FR", "Germany": "DE", "Deutschland": "DE", "United Kingdom": "GB", 
        "Great Britain": "GB", "Spain": "ES", "Italy": "IT", "Netherlands": "NL",
        "Belgium": "BE", "Sweden": "SE", "Norway": "NO", "Denmark": "DK",
        "Switzerland": "CH", "Austria": "AT", "Portugal": "PT", "Finland": "FI",
        
        # Amérique du Nord
        "United States": "US", "Canada": "CA", "Mexico": "MX", "Mexique": "MX",
        
        # Amérique du Sud
        "Brazil": "BR", "Brésil": "BR", "Argentina": "AR", "Argentine": "AR",
        "Chile": "CL", "Chili": "CL", "Colombia": "CO", "Colombie": "CO",
        "Ecuador": "EC", "Équateur": "EC", "Peru": "PE", "Pérou": "PE",
        
        # Asie
        "China": "CN", "Chine": "CN", "Japan": "JP", "Japon": "JP",
        "India": "IN", "Inde": "IN", "South Korea": "KR", "Corée du Sud": "KR",
        "Singapore": "SG", "Singapour": "SG", "Hong Kong": "HK",
        "Thailand": "TH", "Thaïlande": "TH", "Malaysia": "MY", "Malaisie": "MY",
        
        # Afrique
        "South Africa": "ZA", "Afrique du Sud": "ZA", "Egypt": "EG", "Égypte": "EG",
        "Nigeria": "NG", "Kenya": "KE", "Morocco": "MA", "Maroc": "MA",
        
        # Océanie
        "Australia": "AU", "Australie": "AU", "New Zealand": "NZ", "Nouvelle-Zélande": "NZ"
    }
    
    # Si c'est déjà un code à 2 lettres, le retourner en majuscules
    if len(country_name) == 2:
        return country_name.upper()
    
    # Rechercher dans le dictionnaire (insensible à la casse)
    for name, code in country_codes.items():
        if country_name.lower() in name.lower() or name.lower() in country_name.lower():
            return code
    
    # Si non trouvé, retourner US par défaut (plus grande base D&B)
    return "US"

async def try_dnb_match_and_clean(search_request: UnifiedSearchRequest) -> Optional[List[Dict[str, Any]]]:
    """Utilise l'API D&B Match and Clean avec les stratégies GRS (Global Reference Solution)"""
    try:
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        logger.info(f"Using D&B GRS Match and Clean API for search")
        
        # Construire la requête selon les stratégies GRS D&B
        match_request = {}
        search_strategy = "Unknown"
        
        # === STRATÉGIE 1: RECHERCHE PAR IDENTIFIANTS (Priorité maximale) ===
        if search_request.duns:
            match_request["duns"] = search_request.duns
            search_strategy = "DUNS Exact Match"
            logger.info(f"GRS Strategy: DUNS lookup for {search_request.duns}")
            
        elif search_request.local_identifier or search_request.national_id:
            # Identifiant local (nouveau champ GRS) ou national_id (compatibilité)
            identifier = search_request.local_identifier or search_request.national_id
            match_request["nationalRegistrationNumber"] = identifier
            search_strategy = "Local Identifier Match"
            logger.info(f"GRS Strategy: Local identifier lookup for {identifier}")
                
        # === STRATÉGIE 2: RECHERCHE PAR RAISON SOCIALE + GÉOLOCALISATION ===
        elif search_request.company_name:
            match_request["organizationName"] = search_request.company_name
            search_strategy = "Company Name + Address Match"
            logger.info(f"GRS Strategy: Company name search for '{search_request.company_name}'")
            
            # Ajouter géolocalisation par priorité
            if search_request.country:
                country_code = get_country_iso_code(search_request.country)
                match_request["countryISOAlpha2Code"] = country_code
                logger.info(f"GRS Strategy: Country specified - {search_request.country} -> {country_code}")
            
            # Ajouter les critères d'adresse par ordre de priorité GRS
            if search_request.address:
                match_request["streetAddressLine"] = search_request.address
            
            if search_request.city:
                match_request["primaryTownName"] = search_request.city
            
            if search_request.state:
                match_request["addressRegionName"] = search_request.state
            
            if search_request.postal_code:
                match_request["postalCode"] = search_request.postal_code
        
        # === STRATÉGIE 3: RECHERCHE PAR CONTACT ===
        elif search_request.phone_fax or search_request.phone:
            phone_number = search_request.phone_fax or search_request.phone
            match_request["telephoneNumber"] = phone_number
            search_strategy = "Phone/Contact Match"
            logger.info(f"GRS Strategy: Phone/Fax search for {phone_number}")
            
            # Ajouter le pays si disponible pour le contexte téléphonique
            if search_request.country:
                country_code = get_country_iso_code(search_request.country)
                match_request["countryISOAlpha2Code"] = country_code
        
        # Si aucune stratégie principale n'est applicable, recherche géographique large
        else:
            search_strategy = "Geographic/Broad Match"
            if search_request.country:
                country_code = get_country_iso_code(search_request.country)
                match_request["countryISOAlpha2Code"] = country_code
                logger.info(f"GRS Strategy: Geographic search in {search_request.country}")
            else:
                # Recherche par défaut - États-Unis (plus grande base D&B)
                match_request["countryISOAlpha2Code"] = "US"
                logger.info(f"GRS Strategy: Default US search")
        
        # === PARAMÈTRES DE QUALITÉ GRS ===
        match_request["exclusionCriteria"] = [
            "ExcludeOutofBusiness",
            "ExcludeUndeliverable", 
            "ExcludeUnreachable"
        ]
        
        # Ajuster les paramètres selon la stratégie
        if search_request.duns or search_request.local_identifier or search_request.national_id:
            # Recherche précise - critères stricts
            match_request["candidatePerEntityMaximumQuantity"] = 5
            match_request["matchGradeMinimum"] = 6
        elif search_request.company_name and (search_request.address or search_request.city):
            # Recherche standard - critères modérés
            match_request["candidatePerEntityMaximumQuantity"] = 10
            match_request["matchGradeMinimum"] = 4
        else:
            # Recherche étendue - critères plus larges
            match_request["candidatePerEntityMaximumQuantity"] = 15
            match_request["matchGradeMinimum"] = 3
        
        # Faire l'appel à l'API D&B Match and Clean
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{DNB_API_BASE}/v1/match/cleanse",
                headers=headers,
                json=match_request
            )
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"SUCCESS: D&B GRS API returned {response.status_code} with {len(data.get('matchCandidates', []))} candidates")
                
                # Parser les résultats avec ranking GRS
                candidates = data.get("matchCandidates", [])
                
                ranked_results = []
                for candidate in candidates:
                    try:
                        # Extraire les informations de ranking GRS
                        match_grade = candidate.get("matchGrade", 0)
                        confidence_code = candidate.get("confidenceCode", 0)
                        
                        # Organisation data
                        org = candidate.get("organization", {})
                        duns = org.get("duns", "")
                        
                        # Créer le résultat avec ranking GRS
                        result = {
                            "duns": duns,
                            "company_name": org.get("primaryName", ""),
                            "legal_name": org.get("legalName", ""),
                            "address": {
                                "street": org.get("primaryAddress", {}).get("streetAddress", {}).get("line1", ""),
                                "city": org.get("primaryAddress", {}).get("addressLocality", {}).get("name", ""),
                                "state": org.get("primaryAddress", {}).get("addressRegion", {}).get("name", ""),
                                "postal_code": org.get("primaryAddress", {}).get("postalCode", ""),
                                "country": org.get("primaryAddress", {}).get("addressCountry", {}).get("name", "")
                            },
                            "phone": org.get("telephone", [{}])[0].get("telephoneNumber", "") if org.get("telephone") else "",
                            "industry": org.get("primaryIndustryCode", {}).get("usSicV4Description", ""),
                            
                            # Informations de ranking D&B GRS
                            "match_grade": match_grade,
                            "confidence_code": confidence_code,
                            "search_strategy": search_strategy,
                            "ranking_info": {
                                "match_grade": match_grade,
                                "confidence_code": confidence_code,
                                "confidence_description": get_confidence_description(confidence_code),
                                "match_quality": get_match_quality(match_grade),
                                "search_strategy": search_strategy,
                                "is_high_confidence": confidence_code >= 8,
                                "is_recommended": confidence_code >= 6,
                                "grs_score": confidence_code
                            },
                            
                            "search_criteria": search_request.model_dump(exclude_none=True),
                            "data_source": "D&B GRS API",
                            "last_updated": datetime.now().isoformat()
                        }
                        
                        ranked_results.append(result)
                        
                    except Exception as e:
                        logger.error(f"Error parsing GRS candidate: {str(e)}")
                        continue
                
                # Trier par score GRS (confidence_code puis match_grade)
                ranked_results.sort(key=lambda x: (x.get("confidence_code", 0), x.get("match_grade", 0)), reverse=True)
                
                logger.info(f"GRS Search completed: {len(ranked_results)} ranked results returned")
                return ranked_results
                
            else:
                logger.error(f"D&B GRS API error: {response.status_code} - {response.text}")
                return None
                
    except Exception as e:
        logger.error(f"Error in GRS D&B search: {str(e)}")
        return None

async def search_by_registration_number(national_id: str, country: str = None) -> Optional[List[Dict[str, Any]]]:
    """Recherche dans les données cached par numéro d'enregistrement"""
    try:
        logger.info(f"Searching in cached data for registration number: {national_id}")
        
        # Rechercher dans la base de données cached
        query = {
            "$or": [
                {"registration_numbers.registrationNumber": {"$regex": national_id, "$options": "i"}},
                {"registration_numbers.registrationNumber": national_id},
            ]
        }
        
        if country:
            # Ajouter un filtre par pays si spécifié
            country_filter = {
                "$or": [
                    {"primary_address.addressCountry.name": {"$regex": country, "$options": "i"}},
                    {"country_iso_alpha2_code": {"$regex": country, "$options": "i"}}
                ]
            }
            query = {"$and": [query, country_filter]}
        
        # Rechercher dans les données étendues cached
        cached_results = await db.extended_business_partners.find(query).to_list(10)
        
        if cached_results:
            logger.info(f"Found {len(cached_results)} cached results for registration number")
            results = []
            
            for cached in cached_results:
                # Convertir en format de réponse standard
                result = {
                    "duns": cached.get("duns", ""),
                    "company_name": cached.get("primary_name", ""),
                    "legal_name": cached.get("primary_name", ""),  # Utiliser primary_name comme fallback
                    "address": {
                        "street": cached.get("primary_address", {}).get("streetAddress", {}).get("line1", "") if cached.get("primary_address") else "",
                        "city": cached.get("primary_address", {}).get("addressLocality", {}).get("name", "") if cached.get("primary_address") else "",
                        "state": cached.get("primary_address", {}).get("addressRegion", {}).get("name", "") if cached.get("primary_address") else "",
                        "postal_code": cached.get("primary_address", {}).get("postalCode", "") if cached.get("primary_address") else "",
                        "country": cached.get("primary_address", {}).get("addressCountry", {}).get("name", "") if cached.get("primary_address") else ""
                    },
                    "phone": cached.get("telephone", [{}])[0].get("telephoneNumber", "") if cached.get("telephone") else "",
                    "industry": cached.get("primary_industry_code", {}).get("usSicV4Description", "") if cached.get("primary_industry_code") else "",
                    "registration_numbers": cached.get("registration_numbers", []),
                    
                    # Ranking élevé pour correspondance par numéro d'enregistrement
                    "match_grade": 95,
                    "confidence_code": 9,
                    "ranking_info": {
                        "match_grade": 95,
                        "confidence_code": 9,
                        "confidence_description": "Correspondance par numéro d'enregistrement",
                        "match_quality": "Excellente",
                        "is_high_confidence": True,
                        "is_recommended": True
                    },
                    
                    "data_source": "Cache D&B (Recherche par numéro d'enregistrement)"
                }
                results.append(result)
            
            return results
        
        return None
        
    except Exception as e:
        logger.error(f"Error searching by registration number: {str(e)}")
        return None

def get_confidence_description(confidence_code: int) -> str:
    """Retourne la description du niveau de confiance D&B"""
    if confidence_code >= 9:
        return "Correspondance exacte"
    elif confidence_code >= 8:
        return "Correspondance très forte"
    elif confidence_code >= 6:
        return "Correspondance forte"
    elif confidence_code >= 4:
        return "Correspondance modérée"
    else:
        return "Correspondance faible"

def get_match_quality(match_grade: int) -> str:
    """Retourne la qualité de correspondance"""
    if match_grade >= 90:
        return "Excellente"
    elif match_grade >= 80:
        return "Très bonne"
    elif match_grade >= 70:
        return "Bonne"
    elif match_grade >= 60:
        return "Acceptable"
    else:
        return "Limitée"

def create_mock_company_data(search_request: UnifiedSearchRequest) -> List[Dict[str, Any]]:
    """Create mock company data for demonstration purposes"""
    mock_companies = [
        {
            "duns": "804735132",
            "company_name": "Apple Inc.",
            "legal_name": "Apple Inc.",
            "address": {
                "street": "One Apple Park Way",
                "city": "Cupertino",
                "state": "California",
                "postal_code": "95014",
                "country": "United States"
            },
            "mailing_address": {
                "street": "One Apple Park Way",
                "city": "Cupertino",
                "state": "California", 
                "postal_code": "95014",
                "country": "United States"
            },
            "phone": "+1-408-996-1010",
            "fax": "+1-408-996-1011",
            "website": "https://www.apple.com",
            "email": "investor@apple.com",
            "industry": "Computer Hardware, Software & Services",
            "primary_sic_code": "3571",
            "primary_sic_description": "Electronic Computers",
            "naics_code": "334111",
            "naics_description": "Electronic Computer Manufacturing",
            "business_type": "Corporation - Headquarters",
            "legal_form": "Corporation",
            "operating_status": "Active",
            "employee_count": 154000,
            "annual_revenue": "$394,328,000,000",
            "risk_rating": "1",
            "year_started": 1976,
            "registration_numbers": [
                {
                    "type": "Federal Employer Identification Number (EIN)",
                    "number": "94-2404110",
                    "class": "Federal Tax ID",
                    "location": "United States",
                    "is_preferred": True
                },
                {
                    "type": "California Secretary of State Filing Number",
                    "number": "C0390590",
                    "class": "State Registration",
                    "location": "California, USA",
                    "is_preferred": False
                }
            ],
            "data_source": "D&B Mock Data",
            "last_updated": "2025-01-07T16:30:00Z",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "804735100",
                    "primaryName": "Apple Holdings LLC",
                    "isStandalone": False,
                    "address": {
                        "street": "2701 San Tomas Expressway",
                        "city": "Santa Clara",
                        "state": "California",
                        "country": "United States"
                    }
                },
                "domesticUltimate": {
                    "duns": "804735100", 
                    "primaryName": "Apple Holdings LLC",
                    "isStandalone": False,
                    "address": {
                        "street": "2701 San Tomas Expressway",
                        "city": "Santa Clara",
                        "state": "California",
                        "country": "United States"
                    }
                },
                "parent": {
                    "duns": "804735100",
                    "primaryName": "Apple Holdings LLC",
                    "isStandalone": False,
                    "relationshipCode": "PAR",
                    "relationshipDescription": "Parent Company"
                },
                "hierarchyLevel": 1,
                "subsidiaries": [
                    {
                        "duns": "123456001",
                        "primaryName": "Apple Operations International",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456002",
                        "primaryName": "Apple Sales International",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456003",
                        "primaryName": "Apple Distribution International",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456004",
                        "primaryName": "Apple Europe Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456005",
                        "primaryName": "Apple Services EMEA Limited",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456006",
                        "primaryName": "Apple Japan Inc",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Roppongi Hills Mori Tower",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "123456007",
                        "primaryName": "Apple Korea LLC",
                        "isStandalone": False,
                        "relationshipCode": "SUB", 
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Gangnam Finance Center",
                            "city": "Seoul",
                            "state": "Seoul",
                            "country": "South Korea"
                        }
                    },
                    {
                        "duns": "123456008",
                        "primaryName": "Apple China Co Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Shanghai IFC Tower",
                            "city": "Shanghai",
                            "state": "Shanghai",
                            "country": "China"
                        }
                    }
                ],
                "familyTreeMembersCount": 24,
                "familyTreeMembers": [
                    {
                        "duns": "804735100",
                        "primaryName": "Apple Holdings LLC",
                        "relationshipCode": "GUP",
                        "relationshipDescription": "Global Ultimate Parent",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "2701 San Tomas Expressway",
                            "city": "Santa Clara",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "804735132",
                        "primaryName": "Apple Inc.",
                        "relationshipCode": "CUR",
                        "relationshipDescription": "Current Entity",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Apple Park Way",
                            "city": "Cupertino",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123456001",
                        "primaryName": "Apple Operations International",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456002",
                        "primaryName": "Apple Sales International",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456003",
                        "primaryName": "Apple Distribution International",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456004",
                        "primaryName": "Apple Europe Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456005",
                        "primaryName": "Apple Services EMEA Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Hollyhill Industrial Estate",
                            "city": "Cork",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123456006",
                        "primaryName": "Apple Japan Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Roppongi Hills Mori Tower",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "123456007",
                        "primaryName": "Apple Korea LLC",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Gangnam Finance Center",
                            "city": "Seoul",
                            "state": "Seoul",
                            "country": "South Korea"
                        }
                    },
                    {
                        "duns": "123456008",
                        "primaryName": "Apple China Co Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Shanghai IFC Tower",
                            "city": "Shanghai",
                            "state": "Shanghai",
                            "country": "China"
                        }
                    },
                    {
                        "duns": "123456009",
                        "primaryName": "Apple Canada Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "120 Bremner Boulevard",
                            "city": "Toronto",
                            "state": "Ontario",
                            "country": "Canada"
                        }
                    },
                    {
                        "duns": "123456010",
                        "primaryName": "Apple Australia Pty Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Level 3, 20 Martin Place",
                            "city": "Sydney",
                            "state": "New South Wales",
                            "country": "Australia"
                        }
                    },
                    {
                        "duns": "123456011",
                        "primaryName": "Apple France SARL",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "114 Avenue Charles de Gaulle",
                            "city": "Neuilly-sur-Seine",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123456012",
                        "primaryName": "Apple Germany GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Einsteinring 1",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "123456013",
                        "primaryName": "Apple UK Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Stockley Park",
                            "city": "Uxbridge",
                            "state": "Greater London",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123456014",
                        "primaryName": "Apple Italy S.r.l.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Via Amoretti 71",
                            "city": "Milan",
                            "state": "Lombardy",
                            "country": "Italy"
                        }
                    },
                    {
                        "duns": "123456015",
                        "primaryName": "Apple Spain S.L.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Paseo de la Castellana 95",
                            "city": "Madrid",
                            "state": "Madrid",
                            "country": "Spain"
                        }
                    },
                    {
                        "duns": "123456016",
                        "primaryName": "Apple Netherlands B.V.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Strawinskylaan 3127",
                            "city": "Amsterdam",
                            "state": "North Holland",
                            "country": "Netherlands"
                        }
                    },
                    {
                        "duns": "123456017",
                        "primaryName": "Apple Belgium N.V.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Da Vincilaan 5",
                            "city": "Brussels",
                            "state": "Brussels",
                            "country": "Belgium"
                        }
                    },
                    {
                        "duns": "123456018",
                        "primaryName": "Apple Switzerland GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Freigutstrasse 37",
                            "city": "Wallisellen",
                            "state": "Zurich",
                            "country": "Switzerland"
                        }
                    },
                    {
                        "duns": "123456019",
                        "primaryName": "Apple India Private Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "19th Floor, Concorde Tower C",
                            "city": "Mumbai",
                            "state": "Maharashtra",
                            "country": "India"
                        }
                    },
                    {
                        "duns": "123456020",
                        "primaryName": "Apple Singapore Pte Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "1 Infinite Loop",
                            "city": "Singapore",
                            "state": "Singapore",
                            "country": "Singapore"
                        }
                    },
                    {
                        "duns": "123456021",
                        "primaryName": "Apple Mexico S.A. de C.V.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Montes Urales 424",
                            "city": "Mexico City",
                            "state": "Mexico City",
                            "country": "Mexico"
                        }
                    },
                    {
                        "duns": "123456022",
                        "primaryName": "Apple Brasil Ltda",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Av. Engenheiro Luís Carlos Berrini 1681",
                            "city": "São Paulo",
                            "state": "São Paulo",
                            "country": "Brazil"
                        }
                    }
                ]
            }
        },
        {
            "duns": "006073700",
            "company_name": "Microsoft Corporation",
            "legal_name": "Microsoft Corporation",
            "address": {
                "street": "One Microsoft Way",
                "city": "Redmond",
                "state": "Washington",
                "postal_code": "98052",
                "country": "United States"
            },
            "mailing_address": {
                "street": "One Microsoft Way",
                "city": "Redmond", 
                "state": "Washington",
                "postal_code": "98052",
                "country": "United States"
            },
            "phone": "+1-425-882-8080",
            "fax": "+1-425-882-8081",
            "website": "https://www.microsoft.com",
            "email": "info@microsoft.com",
            "industry": "Software Publishers",
            "primary_sic_code": "7372",
            "primary_sic_description": "Prepackaged Software",
            "naics_code": "511210",
            "naics_description": "Software Publishers",
            "business_type": "Corporation - Headquarters",
            "legal_form": "Corporation",
            "operating_status": "Active",
            "employee_count": 221000,
            "annual_revenue": "$211,915,000,000",
            "risk_rating": "1",
            "year_started": 1975,
            "registration_numbers": [
                {
                    "type": "Federal Employer Identification Number (EIN)",
                    "number": "91-1144442",
                    "class": "Federal Tax ID",
                    "location": "United States",
                    "is_preferred": True
                },
                {
                    "type": "Washington Secretary of State Filing Number",
                    "number": "600413485",
                    "class": "State Registration",
                    "location": "Washington, USA",
                    "is_preferred": False
                }
            ],
            "trade_names": ["Microsoft", "Windows", "Office", "Azure"],
            "stock_exchange": "NASDAQ",
            "data_source": "D&B Mock Data",
            "last_updated": "2025-01-07T16:30:00Z",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "006073700",
                    "primaryName": "Microsoft Corporation",
                    "isStandalone": False,
                    "address": {
                        "street": "One Microsoft Way",
                        "city": "Redmond", 
                        "state": "Washington",
                        "country": "United States"
                    }
                },
                "domesticUltimate": {
                    "duns": "006073700",
                    "primaryName": "Microsoft Corporation",
                    "isStandalone": False,
                    "address": {
                        "street": "One Microsoft Way",
                        "city": "Redmond",
                        "state": "Washington", 
                        "country": "United States"
                    }
                },
                "parent": {
                    "duns": "006073700",
                    "primaryName": "Microsoft Corporation",
                    "isStandalone": False,
                    "relationshipCode": "HQ",
                    "relationshipDescription": "Headquarters"
                },
                "hierarchyLevel": 0,
                "subsidiaries": [
                    {
                        "duns": "123457001",
                        "primaryName": "Microsoft Ireland Operations Limited",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Place",
                            "city": "South County Business Park",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123457002",
                        "primaryName": "Microsoft Technology Licensing LLC",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Way",
                            "city": "Redmond",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457003",
                        "primaryName": "LinkedIn Corporation",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "1000 West Maude Avenue",
                            "city": "Sunnyvale",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457004",
                        "primaryName": "Microsoft France",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "39 quai du Président Roosevelt",
                            "city": "Issy-les-Moulineaux",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123457005",
                        "primaryName": "Microsoft UK Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Microsoft Campus",
                            "city": "Thames Valley Park",
                            "state": "Reading",
                            "country": "United Kingdom"
                        }
                    }
                ],
                "familyTreeMembersCount": 12,
                "familyTreeMembers": [
                    {
                        "duns": "006073700",
                        "primaryName": "Microsoft Corporation",
                        "relationshipCode": "HQ",
                        "relationshipDescription": "Global Ultimate",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "One Microsoft Way",
                            "city": "Redmond",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457001",
                        "primaryName": "Microsoft Ireland Operations Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Place",
                            "city": "South County Business Park",
                            "state": "Cork",
                            "country": "Ireland"
                        }
                    },
                    {
                        "duns": "123457002",
                        "primaryName": "Microsoft Technology Licensing LLC",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Way",
                            "city": "Redmond",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457003",
                        "primaryName": "LinkedIn Corporation",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "1000 West Maude Avenue",
                            "city": "Sunnyvale",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457004",
                        "primaryName": "Microsoft France",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "39 quai du Président Roosevelt",
                            "city": "Issy-les-Moulineaux",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123457005",
                        "primaryName": "Microsoft UK Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Microsoft Campus",
                            "city": "Thames Valley Park",
                            "state": "Reading",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123457006",
                        "primaryName": "Microsoft Azure Holdings",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Way",
                            "city": "Redmond",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457007",
                        "primaryName": "Microsoft Gaming",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "One Microsoft Way",
                            "city": "Redmond",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457008",
                        "primaryName": "Activision Blizzard Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Acquired Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "3100 Ocean Park Boulevard",
                            "city": "Santa Monica",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123457009",
                        "primaryName": "Microsoft Deutschland GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Walter-Gropius-Straße 5",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "123457010",
                        "primaryName": "Microsoft Japan Co Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Shinagawa Grand Central Tower",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "123457011",
                        "primaryName": "Microsoft Singapore Pte Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "1 Marina Boulevard",
                            "city": "Singapore",
                            "state": "Singapore",
                            "country": "Singapore"
                        }
                    }
                ]
            }
        },
        {
            "duns": "001570312",
            "company_name": "Google LLC",
            "legal_name": "Google LLC",
            "address": {
                "street": "1600 Amphitheatre Parkway",
                "city": "Mountain View",
                "state": "California",
                "postal_code": "94043",
                "country": "United States"
            },
            "phone": "+1-650-253-0000",
            "website": "https://www.google.com",
            "email": "info@google.com",
            "industry": "Internet Publishing and Broadcasting",
            "business_type": "Limited Liability Company",
            "employee_count": 156000,
            "annual_revenue": "$307,394,000,000",
            "risk_rating": "1",
            "year_started": 1998,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["Google", "YouTube", "Chrome", "Android"],
            "stock_exchange": "NASDAQ",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "123456800",
                    "primaryName": "Alphabet Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "1600 Amphitheatre Parkway",
                        "city": "Mountain View",
                        "state": "California",
                        "country": "United States"
                    }
                },
                "domesticUltimate": {
                    "duns": "123456800",
                    "primaryName": "Alphabet Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "1600 Amphitheatre Parkway",
                        "city": "Mountain View",
                        "state": "California",
                        "country": "United States"
                    }
                },
                "parent": {
                    "duns": "123456800",
                    "primaryName": "Alphabet Inc.",
                    "isStandalone": False,
                    "relationshipCode": "PAR",
                    "relationshipDescription": "Parent Company"
                },
                "hierarchyLevel": 1,
                "subsidiaries": [
                    {
                        "duns": "123456789",
                        "primaryName": "Google France SARL",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "8 Rue de Londres",
                            "city": "Paris",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123456801",
                        "primaryName": "Google UK Limited",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Belgrave House",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123456802",
                        "primaryName": "Google Germany GmbH",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Erika-Mann-Straße 33",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    }
                ],
                "familyTreeMembersCount": 10,
                "familyTreeMembers": [
                    {
                        "duns": "123456800",
                        "primaryName": "Alphabet Inc.",
                        "relationshipCode": "GUP",
                        "relationshipDescription": "Global Ultimate Parent",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "1600 Amphitheatre Parkway",
                            "city": "Mountain View",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "001570312",
                        "primaryName": "Google LLC",
                        "relationshipCode": "CUR",
                        "relationshipDescription": "Current Entity",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "1600 Amphitheatre Parkway",
                            "city": "Mountain View",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "123456789",
                        "primaryName": "Google France SARL",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "8 Rue de Londres",
                            "city": "Paris",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123456801",
                        "primaryName": "Google UK Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Belgrave House",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123456802",
                        "primaryName": "Google Germany GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Erika-Mann-Straße 33",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "123456803",
                        "primaryName": "Google Japan G.K.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Roppongi Hills Mori Tower",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "123456804",
                        "primaryName": "Google Australia Pty Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "48 Pirrama Road",
                            "city": "Sydney",
                            "state": "New South Wales",
                            "country": "Australia"
                        }
                    },
                    {
                        "duns": "123456805",
                        "primaryName": "Google Canada Corporation",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "111 Richmond Street West",
                            "city": "Toronto",
                            "state": "Ontario",
                            "country": "Canada"
                        }
                    },
                    {
                        "duns": "123456806",
                        "primaryName": "Google India Private Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "3rd Floor, RMZ Infinity Tower C",
                            "city": "Bangalore",
                            "state": "Karnataka",
                            "country": "India"
                        }
                    },
                    {
                        "duns": "123456807",
                        "primaryName": "Google Brazil Internet Ltda",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Av. Brigadeiro Faria Lima 3729",
                            "city": "São Paulo",
                            "state": "São Paulo",
                            "country": "Brazil"
                        }
                    }
                ]
            }
        },
        {
            "duns": "281508188",
            "company_name": "Duns AB",
            "legal_name": "Duns AB",
            "address": {
                "street": "Follingbo Hallfrede 704",
                "city": "Visby",
                "state": "Gotland County",
                "postal_code": "621 91",
                "country": "Sweden"
            },
            "phone": "+46-90-7863990",
            "website": "https://www.duns.se",
            "email": "info@duns.se",
            "industry": "Computer Programming and Consultancy",
            "business_type": "Private Limited Company",
            "employee_count": 25,
            "annual_revenue": "$2,500,000",
            "risk_rating": "2",
            "year_started": 1995,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["Duns"],
            "stock_exchange": "N/A"
        },
        {
            "duns": "123456789",
            "company_name": "Google France SARL",
            "legal_name": "Google France SARL",
            "address": {
                "street": "8 Rue de Londres",
                "city": "Paris",
                "state": "Île-de-France",
                "postal_code": "75009",
                "country": "France"
            },
            "phone": "+33-1-42-68-53-00",
            "website": "https://www.google.fr",
            "email": "info@google.fr",
            "industry": "Internet Publishing and Broadcasting",
            "business_type": "SARL",
            "employee_count": 800,
            "annual_revenue": "€2,500,000,000",
            "risk_rating": "1",
            "year_started": 2000,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["Google France"],
            "stock_exchange": "N/A",
            # Registration numbers for France
            "registration_numbers": [
                {"number": "42472840000021", "type": "SIRET", "class": "Établissement", "is_preferred": True, "location": "Paris"},
                {"number": "424728400", "type": "SIREN", "class": "Entreprise", "is_preferred": False, "location": "Paris"},
                {"number": "FR19424728400", "type": "TVA Intracommunautaire", "class": "Fiscal", "is_preferred": False, "location": "France"}
            ]
        },
        {
            "duns": "987654321",
            "company_name": "Tesla Inc.",
            "legal_name": "Tesla Inc.",
            "address": {
                "street": "1 Tesla Road",
                "city": "Austin",
                "state": "Texas",
                "postal_code": "78725",
                "country": "United States"
            },
            "phone": "+1-512-516-8177",
            "website": "https://www.tesla.com",
            "email": "info@tesla.com",
            "industry": "Motor Vehicle Manufacturing",
            "business_type": "Corporation",
            "employee_count": 127855,
            "annual_revenue": "$96,773,000,000",
            "risk_rating": "2",
            "year_started": 2003,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["Tesla", "Model S", "Model 3", "Model X", "Model Y"],
            "stock_exchange": "NASDAQ",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "987654321",
                    "primaryName": "Tesla Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "1 Tesla Road",
                        "city": "Austin",
                        "state": "Texas",
                        "country": "United States"
                    }
                },
                "domesticUltimate": {
                    "duns": "987654321",
                    "primaryName": "Tesla Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "1 Tesla Road",
                        "city": "Austin",
                        "state": "Texas",
                        "country": "United States"
                    }
                },
                "hierarchyLevel": 0,
                "subsidiaries": [
                    {
                        "duns": "987654322",
                        "primaryName": "Tesla Motors Netherlands B.V.",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Taurusavenue 83",
                            "city": "Hoofddorp",
                            "state": "North Holland",
                            "country": "Netherlands"
                        }
                    },
                    {
                        "duns": "987654323",
                        "primaryName": "Tesla Germany GmbH",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Freie-Vogel-Straße 3",
                            "city": "Berlin",
                            "state": "Berlin",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "987654324",
                        "primaryName": "Tesla China Co Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "No. 1 Jingyang Road",
                            "city": "Shanghai",
                            "state": "Shanghai",
                            "country": "China"
                        }
                    },
                    {
                        "duns": "987654325",
                        "primaryName": "Tesla UK Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Dashwood House",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "987654326",
                        "primaryName": "Tesla Energy Operations Inc",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "901 Page Avenue",
                            "city": "Fremont",
                            "state": "California",
                            "country": "United States"
                        }
                    }
                ],
                "familyTreeMembersCount": 8,
                "familyTreeMembers": [
                    {
                        "duns": "987654321",
                        "primaryName": "Tesla Inc.",
                        "relationshipCode": "HQ",
                        "relationshipDescription": "Headquarters",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "1 Tesla Road",
                            "city": "Austin",
                            "state": "Texas",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "987654322",
                        "primaryName": "Tesla Motors Netherlands B.V.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Taurusavenue 83",
                            "city": "Hoofddorp",
                            "state": "North Holland",
                            "country": "Netherlands"
                        }
                    },
                    {
                        "duns": "987654323",
                        "primaryName": "Tesla Germany GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Freie-Vogel-Straße 3",
                            "city": "Berlin",
                            "state": "Berlin",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "987654324",
                        "primaryName": "Tesla China Co Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "No. 1 Jingyang Road",
                            "city": "Shanghai",
                            "state": "Shanghai",
                            "country": "China"
                        }
                    },
                    {
                        "duns": "987654325",
                        "primaryName": "Tesla UK Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Dashwood House",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "987654326",
                        "primaryName": "Tesla Energy Operations Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "901 Page Avenue",
                            "city": "Fremont",
                            "state": "California",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "987654327",
                        "primaryName": "Tesla France SAS",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Tour Atlantique",
                            "city": "Paris",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "987654328",
                        "primaryName": "Tesla Australia Pty Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Level 14, 56 Pitt Street",
                            "city": "Sydney",
                            "state": "New South Wales",
                            "country": "Australia"
                        }
                    }
                ]
            }
        },
        {
            "duns": "555666777",
            "company_name": "Amazon.com Inc.",
            "legal_name": "Amazon.com Inc.",
            "address": {
                "street": "410 Terry Avenue North",
                "city": "Seattle",
                "state": "Washington",
                "postal_code": "98109",
                "country": "United States"
            },
            "phone": "+1-206-266-1000",
            "website": "https://www.amazon.com",
            "email": "info@amazon.com",
            "industry": "Electronic Shopping and Mail-Order Houses",
            "business_type": "Corporation",
            "employee_count": 1541000,
            "annual_revenue": "$574,785,000,000",
            "risk_rating": "1",
            "year_started": 1994,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["Amazon", "AWS", "Prime", "Alexa"],
            "stock_exchange": "NASDAQ",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "555666777",
                    "primaryName": "Amazon.com Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "410 Terry Avenue North",
                        "city": "Seattle",
                        "state": "Washington",
                        "country": "United States"
                    }
                },
                "domesticUltimate": {
                    "duns": "555666777",
                    "primaryName": "Amazon.com Inc.",
                    "isStandalone": False,
                    "address": {
                        "street": "410 Terry Avenue North",
                        "city": "Seattle",
                        "state": "Washington",
                        "country": "United States"
                    }
                },
                "hierarchyLevel": 0,
                "subsidiaries": [
                    {
                        "duns": "555666778",
                        "primaryName": "Amazon Web Services Inc",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "410 Terry Avenue North",
                            "city": "Seattle",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "555666779",
                        "primaryName": "Amazon UK Services Ltd",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "60 Holborn Viaduct",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "555666780",
                        "primaryName": "Amazon Germany GmbH",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Krausenstraße 38",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "555666781",
                        "primaryName": "Amazon France Logistique",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "67 Boulevard du Général Leclerc",
                            "city": "Clichy",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "555666782",
                        "primaryName": "Amazon Japan G.K.",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Arco Tower Annex",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "555666783",
                        "primaryName": "Whole Foods Market Inc",
                        "isStandalone": False,
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Acquired Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "550 Bowie Street",
                            "city": "Austin",
                            "state": "Texas",
                            "country": "United States"
                        }
                    }
                ],
                "familyTreeMembersCount": 12,
                "familyTreeMembers": [
                    {
                        "duns": "555666777",
                        "primaryName": "Amazon.com Inc.",
                        "relationshipCode": "HQ",
                        "relationshipDescription": "Headquarters",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "410 Terry Avenue North",
                            "city": "Seattle",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "555666778",
                        "primaryName": "Amazon Web Services Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "410 Terry Avenue North",
                            "city": "Seattle",
                            "state": "Washington",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "555666779",
                        "primaryName": "Amazon UK Services Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "60 Holborn Viaduct",
                            "city": "London",
                            "state": "England",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "555666780",
                        "primaryName": "Amazon Germany GmbH",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Krausenstraße 38",
                            "city": "Munich",
                            "state": "Bavaria",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "555666781",
                        "primaryName": "Amazon France Logistique",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "67 Boulevard du Général Leclerc",
                            "city": "Clichy",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "555666782",
                        "primaryName": "Amazon Japan G.K.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Arco Tower Annex",
                            "city": "Tokyo",
                            "state": "Tokyo",
                            "country": "Japan"
                        }
                    },
                    {
                        "duns": "555666783",
                        "primaryName": "Whole Foods Market Inc",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Acquired Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "550 Bowie Street",
                            "city": "Austin",
                            "state": "Texas",
                            "country": "United States"
                        }
                    },
                    {
                        "duns": "555666784",
                        "primaryName": "Amazon India Private Limited",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "8th Floor, Brigade Gateway",
                            "city": "Bangalore",
                            "state": "Karnataka",
                            "country": "India"
                        }
                    },
                    {
                        "duns": "555666785",
                        "primaryName": "Amazon Australia Pty Ltd",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Level 37, 2 Park Street",
                            "city": "Sydney",
                            "state": "New South Wales",
                            "country": "Australia"
                        }
                    },
                    {
                        "duns": "555666786",
                        "primaryName": "Amazon Canada Fulfillment Services",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "120 Bremner Boulevard",
                            "city": "Toronto",
                            "state": "Ontario",
                            "country": "Canada"
                        }
                    },
                    {
                        "duns": "555666787",
                        "primaryName": "Amazon Spain Services S.L.U.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Calle Ramirez de Prado 5",
                            "city": "Madrid",
                            "state": "Madrid",
                            "country": "Spain"
                        }
                    },
                    {
                        "duns": "555666788",
                        "primaryName": "Amazon Italy Services S.r.l.",
                        "relationshipCode": "SUB",
                        "relationshipDescription": "Wholly Owned Subsidiary",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Viale Monte Grappa 3/5",
                            "city": "Milan",
                            "state": "Lombardy",
                            "country": "Italy"
                        }
                    }
                ]
            }
        },
        {
            "duns": "555444333",
            "company_name": "1-700 Digital Misedi S.A.",
            "legal_name": "1-700 Digital Misedi S.A.",
            "address": {
                "street": "Av. Rodrigo Chavez",
                "city": "Quito",
                "state": "Pichincha",
                "postal_code": "170143",
                "country": "Ecuador"
            },
            "phone": "+593-2-234-5678",
            "website": "https://www.1700digital.com",
            "email": "info@1700digital.com",
            "industry": "Software Development",
            "business_type": "Sociedad Anónima",
            "employee_count": 45,
            "annual_revenue": "$2,300,000",
            "risk_rating": "2",
            "year_started": 2018,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["1-700 Digital", "Misedi"],
            "stock_exchange": "N/A",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "555444333",
                    "primaryName": "1-700 Digital Misedi S.A.",
                    "isStandalone": True,
                    "address": {
                        "street": "Av. Rodrigo Chavez",
                        "city": "Quito",
                        "state": "Pichincha",
                        "country": "Ecuador"
                    }
                },
                "domesticUltimate": {
                    "duns": "555444333",
                    "primaryName": "1-700 Digital Misedi S.A.",
                    "isStandalone": True,
                    "address": {
                        "street": "Av. Rodrigo Chavez",
                        "city": "Quito",
                        "state": "Pichincha",
                        "country": "Ecuador"
                    }
                },
                "hierarchyLevel": 0,
                "subsidiaries": [],
                "familyTreeMembersCount": 1,
                "familyTreeMembers": [
                    {
                        "duns": "555444333",
                        "primaryName": "1-700 Digital Misedi S.A.",
                        "relationshipCode": "HQ",
                        "relationshipDescription": "Standalone Entity",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "Av. Rodrigo Chavez",
                            "city": "Quito",
                            "state": "Pichincha",
                            "country": "Ecuador"
                        }
                    }
                ]
            },
            "registration_numbers": [
                {
                    "number": "1792584567001",
                    "type": "RUC",
                    "class": "Empresa",
                    "is_preferred": True,
                    "location": "Ecuador"
                },
                {
                    "number": "EC-1792584567",
                    "type": "Registro Mercantil",
                    "class": "Comercial",
                    "is_preferred": False,
                    "location": "Quito"
                }
            ]
        },
        {
            "duns": "004438398",
            "company_name": "IONOS SARL",
            "legal_name": "IONOS SARL",
            "address": {
                "street": "7 Place de la Gare",
                "city": "Sarreguemines",
                "state": "Grand Est",
                "postal_code": "57200",
                "country": "France"
            },
            "mailing_address": {
                "street": "7 Place de la Gare",
                "city": "Sarreguemines",
                "state": "Grand Est", 
                "postal_code": "57200",
                "country": "France"
            },
            "phone": "+33-9-70-80-89-11",
            "fax": "+33-9-70-80-89-12",
            "website": "https://www.ionos.fr",
            "email": "contact@ionos.fr",
            "industry": "Computer Programming and Consultancy",
            "primary_sic_code": "7371",
            "primary_sic_description": "Computer Programming Services",
            "naics_code": "541511",
            "naics_description": "Custom Computer Programming Services",
            "business_type": "SARL - Siège social",
            "legal_form": "SARL",
            "operating_status": "Active",
            "employee_count": 25,
            "annual_revenue": "€2,500,000",
            "risk_rating": "2",
            "year_started": 1995,
            "registration_numbers": [
                {
                    "type": "SIRET",
                    "number": "52198765400015",
                    "class": "Établissement",
                    "location": "France",
                    "is_preferred": True
                },
                {
                    "type": "SIREN", 
                    "number": "521987654",
                    "class": "Entreprise",
                    "location": "France",
                    "is_preferred": False
                },
                {
                    "type": "TVA Intracommunautaire",
                    "number": "FR19521987654",
                    "class": "Fiscal",
                    "location": "France",
                    "is_preferred": False
                }
            ],
            "trade_names": ["IONOS"],
            "stock_exchange": "N/A",
            "data_source": "D&B Mock Data",
            "last_updated": "2025-01-07T16:30:00Z",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "123456789",
                    "primaryName": "United Internet AG",
                    "isStandalone": False,
                    "address": {
                        "street": "Elgendorfer Straße 57",
                        "city": "Montabaur",
                        "state": "Rhineland-Palatinate",
                        "country": "Germany"
                    }
                },
                "domesticUltimate": {
                    "duns": "123456790",
                    "primaryName": "IONOS SE",
                    "isStandalone": False,
                    "address": {
                        "street": "Elgendorfer Straße 57",
                        "city": "Montabaur",
                        "state": "Rhineland-Palatinate",
                        "country": "Germany"
                    }
                },
                "parent": {
                    "duns": "123456790",
                    "primaryName": "IONOS SE",
                    "isStandalone": False,
                    "relationshipCode": "PAR",
                    "relationshipDescription": "Parent Company"
                },
                "hierarchyLevel": 2,
                "subsidiaries": [
                    {
                        "duns": "111222333",
                        "primaryName": "IONOS SARL Puteaux",
                        "isStandalone": False,
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "27 COURS VALMY",
                            "city": "PUTEAUX",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    }
                ],
                "familyTreeMembersCount": 8,
                "familyTreeMembers": [
                    {
                        "duns": "123456789",
                        "primaryName": "United Internet AG",
                        "relationshipCode": "GUP",
                        "relationshipDescription": "Global Ultimate Parent",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "Elgendorfer Straße 57",
                            "city": "Montabaur",
                            "state": "Rhineland-Palatinate",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "123456790",
                        "primaryName": "IONOS SE",
                        "relationshipCode": "PAR",
                        "relationshipDescription": "Parent Company",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Elgendorfer Straße 57",
                            "city": "Montabaur",
                            "state": "Rhineland-Palatinate",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "004438398",
                        "primaryName": "IONOS SARL",
                        "relationshipCode": "CUR",
                        "relationshipDescription": "Current Entity",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "7 Place de la Gare",
                            "city": "Sarreguemines",
                            "state": "Grand Est",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "111222333",
                        "primaryName": "IONOS SARL Puteaux",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "27 COURS VALMY",
                            "city": "PUTEAUX",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123456791",
                        "primaryName": "IONOS UK Ltd",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Digbeth Court",
                            "city": "Birmingham",
                            "state": "West Midlands",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123456792",
                        "primaryName": "IONOS Spain S.L.",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Calle Raimundo Fernández Villaverde 65",
                            "city": "Madrid",
                            "state": "Madrid",
                            "country": "Spain"
                        }
                    },
                    {
                        "duns": "123456793",
                        "primaryName": "IONOS Italy S.r.l.",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Via Caldera 21",
                            "city": "Milan",
                            "state": "Lombardy",
                            "country": "Italy"
                        }
                    },
                    {
                        "duns": "123456794",
                        "primaryName": "IONOS USA Inc",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "701 Lee Street",
                            "city": "Chesterbrook",
                            "state": "Pennsylvania",
                            "country": "United States"
                        }
                    }
                ]
            },
            "registration_numbers": [
                {
                    "number": "52198765400015",
                    "type": "SIRET",
                    "class": "Établissement",
                    "is_preferred": True,
                    "location": "SARREGUEMINES"
                },
                {
                    "number": "521987654",
                    "type": "SIREN",
                    "class": "Entreprise",
                    "is_preferred": False,
                    "location": "SARREGUEMINES"
                },
                {
                    "number": "FR25521987654",
                    "type": "TVA Intracommunautaire",
                    "class": "Fiscal",
                    "is_preferred": False,
                    "location": "France"
                }
            ]
        },
        {
            "duns": "111222333",
            "company_name": "IONOS SARL",
            "legal_name": "IONOS SARL",
            "address": {
                "street": "27 COURS VALMY",
                "city": "PUTEAUX",
                "state": "Île-de-France",
                "postal_code": "92800",
                "country": "France"
            },
            "phone": "+33-1-41-40-20-30",
            "website": "https://www.ionos.fr",
            "email": "contact@ionos.fr",
            "industry": "Web Hosting Services",
            "business_type": "SARL",
            "employee_count": 125,
            "annual_revenue": "€15,800,000",
            "risk_rating": "1",
            "year_started": 2005,
            "status": "Active",
            "operating_status": "Active",
            "trade_names": ["IONOS", "1&1 IONOS"],
            "stock_exchange": "N/A",
            "corporate_hierarchy": {
                "globalUltimate": {
                    "duns": "123456789",
                    "primaryName": "United Internet AG",
                    "isStandalone": False,
                    "address": {
                        "street": "Elgendorfer Straße 57",
                        "city": "Montabaur",
                        "state": "Rhineland-Palatinate",
                        "country": "Germany"
                    }
                },
                "domesticUltimate": {
                    "duns": "123456790",
                    "primaryName": "IONOS SE",
                    "isStandalone": False,
                    "address": {
                        "street": "Elgendorfer Straße 57",
                        "city": "Montabaur",
                        "state": "Rhineland-Palatinate",
                        "country": "Germany"
                    }
                },
                "parent": {
                    "duns": "123456790",
                    "primaryName": "IONOS SE",
                    "isStandalone": False,
                    "relationshipCode": "PAR",
                    "relationshipDescription": "Parent Company"
                },
                "hierarchyLevel": 2,
                "subsidiaries": [
                    {
                        "duns": "004438398",
                        "primaryName": "IONOS SARL Sarreguemines",
                        "isStandalone": False,
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "7 Place de la Gare",
                            "city": "Sarreguemines",
                            "state": "Grand Est",
                            "country": "France"
                        }
                    }
                ],
                "familyTreeMembersCount": 8,
                "familyTreeMembers": [
                    {
                        "duns": "123456789",
                        "primaryName": "United Internet AG",
                        "relationshipCode": "GUP",
                        "relationshipDescription": "Global Ultimate Parent",
                        "hierarchyLevel": 0,
                        "address": {
                            "street": "Elgendorfer Straße 57",
                            "city": "Montabaur",
                            "state": "Rhineland-Palatinate",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "123456790",
                        "primaryName": "IONOS SE",
                        "relationshipCode": "PAR",
                        "relationshipDescription": "Parent Company",
                        "hierarchyLevel": 1,
                        "address": {
                            "street": "Elgendorfer Straße 57",
                            "city": "Montabaur",
                            "state": "Rhineland-Palatinate",
                            "country": "Germany"
                        }
                    },
                    {
                        "duns": "111222333",
                        "primaryName": "IONOS SARL Puteaux",
                        "relationshipCode": "CUR",
                        "relationshipDescription": "Current Entity",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "27 COURS VALMY",
                            "city": "PUTEAUX",
                            "state": "Île-de-France",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "004438398",
                        "primaryName": "IONOS SARL Sarreguemines",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "7 Place de la Gare",
                            "city": "Sarreguemines",
                            "state": "Grand Est",
                            "country": "France"
                        }
                    },
                    {
                        "duns": "123456791",
                        "primaryName": "IONOS UK Ltd",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Digbeth Court",
                            "city": "Birmingham",
                            "state": "West Midlands",
                            "country": "United Kingdom"
                        }
                    },
                    {
                        "duns": "123456792",
                        "primaryName": "IONOS Spain S.L.",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Calle Raimundo Fernández Villaverde 65",
                            "city": "Madrid",
                            "state": "Madrid",
                            "country": "Spain"
                        }
                    },
                    {
                        "duns": "123456793",
                        "primaryName": "IONOS Italy S.r.l.",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "Via Caldera 21",
                            "city": "Milan",
                            "state": "Lombardy",
                            "country": "Italy"
                        }
                    },
                    {
                        "duns": "123456794",
                        "primaryName": "IONOS USA Inc",
                        "relationshipCode": "SIS",
                        "relationshipDescription": "Sister Company",
                        "hierarchyLevel": 2,
                        "address": {
                            "street": "701 Lee Street",
                            "city": "Chesterbrook",
                            "state": "Pennsylvania",
                            "country": "United States"
                        }
                    }
                ]
            },
            "registration_numbers": [
                {
                    "number": "41234567800018",
                    "type": "SIRET",
                    "class": "Établissement",
                    "is_preferred": True,
                    "location": "PUTEAUX"
                },
                {
                    "number": "412345678",
                    "type": "SIREN",
                    "class": "Entreprise",
                    "is_preferred": False,
                    "location": "PUTEAUX"
                },
                {
                    "number": "FR18412345678",
                    "type": "TVA Intracommunautaire",
                    "class": "Fiscal",
                    "is_preferred": False,
                    "location": "France"
                }
            ]
        }
    ]
    
    # Enhanced filtering based on search criteria
    filtered_companies = []
    for company in mock_companies:
        match = True
        
        # Existing filters
        if search_request.company_name:
            if search_request.company_name.lower() not in company["company_name"].lower():
                match = False
                
        if search_request.duns:
            if search_request.duns != company["duns"]:
                match = False
                
        if search_request.city:
            if search_request.city.lower() not in company["address"]["city"].lower():
                match = False
                
        if search_request.country:
            if search_request.country.lower() not in company["address"]["country"].lower():
                match = False
        
        # Address filters
        if search_request.address:
            # Vérifier si l'adresse recherchée est présente dans l'adresse de rue de l'entreprise
            if search_request.address.lower() not in company["address"]["street"].lower():
                match = False
        
        # New address filters
        if search_request.street_address:
            if search_request.street_address.lower() not in company["address"]["street"].lower():
                match = False
                
        if search_request.state:
            if search_request.state.lower() not in company["address"]["state"].lower():
                match = False
                
        if search_request.postal_code:
            if search_request.postal_code not in company["address"]["postal_code"]:
                match = False
        
        # Contact filters
        if search_request.phone:
            if search_request.phone not in company["phone"]:
                match = False
                
        if search_request.website:
            if search_request.website.lower() not in company["website"].lower():
                match = False
                
        if search_request.email:
            if search_request.email.lower() not in company["email"].lower():
                match = False
        
        # Business characteristic filters
        if search_request.industry:
            if search_request.industry.lower() not in company["industry"].lower():
                match = False
                
        if search_request.business_type:
            if search_request.business_type.lower() not in company["business_type"].lower():
                match = False
                
        if search_request.operating_status:
            if search_request.operating_status.lower() not in company["operating_status"].lower():
                match = False
                
        # Employee count range
        if search_request.employee_count_min:
            if company["employee_count"] < search_request.employee_count_min:
                match = False
                
        if search_request.employee_count_max:
            if company["employee_count"] > search_request.employee_count_max:
                match = False
                
        # Year started range
        if search_request.year_started_min:
            if company["year_started"] < search_request.year_started_min:
                match = False
                
        if search_request.year_started_max:
            if company["year_started"] > search_request.year_started_max:
                match = False
                
        # Legal name filter
        if search_request.legal_name:
            if search_request.legal_name.lower() not in company["legal_name"].lower():
                match = False
                
        # Trade name filter
        if search_request.trade_name:
            trade_match = False
            for trade_name in company.get("trade_names", []):
                if search_request.trade_name.lower() in trade_name.lower():
                    trade_match = True
                    break
            if not trade_match:
                match = False
                
        # Stock exchange filter
        if search_request.stock_exchange:
            if search_request.stock_exchange.lower() not in company["stock_exchange"].lower():
                match = False
        
        # Registration number search
        if search_request.national_id or search_request.local_identifier:
            reg_match = False
            search_identifier = search_request.local_identifier or search_request.national_id
            if "registration_numbers" in company:
                for reg in company["registration_numbers"]:
                    if search_identifier in reg["number"]:
                        reg_match = True
                        break
            if not reg_match:
                match = False
                
        if match:
            # Add search criteria info
            company["search_criteria"] = {
                "company_name": search_request.company_name,
                "duns": search_request.duns,
                "address": search_request.address,
                "street_address": search_request.street_address,
                "city": search_request.city,
                "state": search_request.state,
                "postal_code": search_request.postal_code,
                "country": search_request.country,
                "national_id": search_request.national_id,
                "phone": search_request.phone,
                "website": search_request.website,
                "email": search_request.email,
                "industry": search_request.industry,
                "business_type": search_request.business_type,
                "employee_count_min": search_request.employee_count_min,
                "employee_count_max": search_request.employee_count_max,
                "year_started_min": search_request.year_started_min,
                "year_started_max": search_request.year_started_max,
                "operating_status": search_request.operating_status,
                "legal_name": search_request.legal_name,
                "trade_name": search_request.trade_name,
                "stock_exchange": search_request.stock_exchange
            }
            
            # Create BusinessPartnerInfo but include corporate_hierarchy in the dict
            business_info = BusinessPartnerInfo(**company)
            business_dict = business_info.model_dump()
            
            # Add corporate_hierarchy if it exists in the original company data
            if "corporate_hierarchy" in company:
                business_dict["corporate_hierarchy"] = company["corporate_hierarchy"]
            
            # Add registration_numbers if they exist in the original company data
            if "registration_numbers" in company:
                business_dict["registration_numbers"] = company["registration_numbers"]
            
            filtered_companies.append(business_dict)
    
    return filtered_companies

@api_router.get("/company-hierarchy/{duns}")
async def get_company_hierarchy(duns: str, current_user: str = Depends(get_current_user)):
    """Récupère les informations de hiérarchie corporative pour un DUNS donné"""
    try:
        # Valider le DUNS
        if not duns or len(duns.replace(' ', '').replace('-', '')) not in [9, 10]:
            raise HTTPException(status_code=400, detail="DUNS number must be 9 or 10 digits")
        
        # Nettoyer le DUNS
        cleaned_duns = duns.replace(' ', '').replace('-', '')
        if len(cleaned_duns) == 10 and cleaned_duns.startswith('0'):
            cleaned_duns = cleaned_duns[1:]
        
        logger.info(f"Fetching hierarchy for DUNS: {cleaned_duns}")
        
        # Récupérer les informations de hiérarchie depuis D&B
        corporate_hierarchy = await get_corporate_hierarchy(cleaned_duns)
        
        if not corporate_hierarchy:
            # Essayer de récupérer la family tree comme fallback
            family_tree = await get_family_tree(cleaned_duns)
            if family_tree:
                corporate_hierarchy = CorporateHierarchy(
                    familyTreeMembers=family_tree,
                    familyTreeMembersCount=len(family_tree)
                )
        
        # Si pas de données D&B, essayer les données mock
        if not corporate_hierarchy:
            logger.info(f"No D&B hierarchy data found for DUNS {cleaned_duns}, checking mock data")
            
            # Utiliser les données mock de create_mock_company_data
            from pydantic import BaseModel
            
            class MockSearchRequest(BaseModel):
                duns: str = cleaned_duns
                
            mock_search_request = MockSearchRequest(duns=cleaned_duns)
            mock_companies = create_mock_company_data(mock_search_request)
            
            # Chercher l'entreprise correspondante
            matching_company = None
            for company in mock_companies:
                if company["duns"] == cleaned_duns:
                    matching_company = company
                    break
            
            if matching_company and "corporate_hierarchy" in matching_company:
                logger.info(f"Found mock hierarchy data for DUNS {cleaned_duns}")
                hierarchy_data = matching_company["corporate_hierarchy"]
                
                corporate_hierarchy = CorporateHierarchy(
                    familyTreeMembersCount=hierarchy_data.get("familyTreeMembersCount", 0),
                    familyTreeMembers=hierarchy_data.get("familyTreeMembers", []),
                    hierarchyLevel=hierarchy_data.get("hierarchyLevel", 0),
                    globalUltimate=hierarchy_data.get("globalUltimate"),
                    domesticUltimate=hierarchy_data.get("domesticUltimate"),
                    parent=hierarchy_data.get("parent"),
                    subsidiaries=hierarchy_data.get("subsidiaries", [])
                )
            else:
                logger.warning(f"No mock hierarchy data found for DUNS {cleaned_duns}")
                return {
                    "duns": cleaned_duns,
                    "hierarchy": None,
                    "message": "No hierarchy information found",
                    "data_source": "Mock fallback - no data"
                }
        
        if corporate_hierarchy:
            return {
                "duns": cleaned_duns,
                "hierarchy": corporate_hierarchy.model_dump(),
                "data_source": "D&B Hierarchy API"
            }
        else:
            return {
                "duns": cleaned_duns,
                "hierarchy": None,
                "message": "No hierarchy information found",
                "data_source": "D&B Hierarchy API"
            }
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in company hierarchy endpoint: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.get("/test-dnb-auth")
async def test_dnb_authentication():
    """Teste l'authentification D&B avec les tokens configurés"""
    try:
        # Tester l'obtention du token
        token = await get_cached_token()
        
        if not token:
            return {
                "status": "error",
                "message": "Failed to obtain D&B token",
                "details": "Check DUNS_CONSUMER_KEY and DUNS_CONSUMER_SECRET"
            }
        
        # Vérifier que le token n'est pas vide et a une longueur raisonnable
        if len(token) < 10:
            return {
                "status": "error", 
                "message": "Invalid token received",
                "token_length": len(token)
            }
        
        # Tester un appel simple à l'API D&B pour vérifier que le token fonctionne
        headers = {"Authorization": f"Bearer {token}"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Test avec un DUNS connu qui devrait exister
            test_response = await client.get(
                f"{DNB_API_BASE}/v1/data/duns/804735132?blockIDs=companyinfo_L1_v1",
                headers=headers
            )
            
            return {
                "status": "success",
                "message": "D&B authentication successful",
                "token_length": len(token),
                "token_preview": f"{token[:10]}...{token[-10:]}",
                "api_test": {
                    "endpoint": f"{DNB_API_BASE}/v1/data/duns/804735132",
                    "status_code": test_response.status_code,
                    "response_size": len(test_response.text),
                    "has_organization_data": "organization" in test_response.text.lower()
                },
                "credentials_source": "Environment variables",
                "consumer_key_preview": f"{os.environ.get('DUNS_CONSUMER_KEY', '')[:10]}..."
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"D&B authentication test failed: {str(e)}",
            "error_type": type(e).__name__
        }

@api_router.get("/test-dnb-match")
async def test_dnb_match_api():
    """Teste l'API D&B Match and Clean avec les tokens"""
    try:
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test avec une requête Match and Clean simple
        match_request = {
            "organizationName": "Apple Inc",
            "countryISOAlpha2Code": "US",
            "exclusionCriteria": [
                "ExcludeOutofBusiness",
                "ExcludeUndeliverable", 
                "ExcludeUnreachable"
            ],
            "candidatePerEntityMaximumQuantity": 5,
            "matchGradeMinimum": 3
        }
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{DNB_API_BASE}/v1/match/cleanse",
                headers=headers,
                json=match_request
            )
            
            result = {
                "status": "success" if response.status_code == 200 else "error",
                "api_endpoint": f"{DNB_API_BASE}/v1/match/cleanse",
                "status_code": response.status_code,
                "request_sent": match_request,
                "response_size": len(response.text),
                "content_type": response.headers.get("content-type", "unknown")
            }
            
            if response.status_code == 200:
                data = response.json()
                result["match_candidates_count"] = len(data.get("matchCandidates", []))
                result["has_organization_data"] = any("organization" in str(candidate) for candidate in data.get("matchCandidates", []))
            else:
                result["error_response"] = response.text[:500]  # Premiers 500 caractères
            
            return result
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"D&B Match API test failed: {str(e)}",
            "error_type": type(e).__name__
        }

@api_router.get("/test-dnb-hierarchy")
async def test_dnb_hierarchy_api():
    """Teste l'API D&B Hierarchy avec les tokens"""
    try:
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        # Test avec un DUNS connu
        test_duns = "804735132"
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            # Test Hierarchy and Connections L1
            hierarchy_response = await client.get(
                f"{DNB_API_BASE}/v1/data/duns/{test_duns}?blockIDs=hierarchyconnections_L1_v1",
                headers=headers
            )
            
            # Test Family Tree
            family_tree_response = await client.get(
                f"{DNB_API_BASE}/v1/familytree/{test_duns}?hierarchyDirection=upward",
                headers=headers
            )
            
            return {
                "status": "success",
                "test_duns": test_duns,
                "hierarchy_api": {
                    "endpoint": f"{DNB_API_BASE}/v1/data/duns/{test_duns}?blockIDs=hierarchyconnections_L1_v1",
                    "status_code": hierarchy_response.status_code,
                    "response_size": len(hierarchy_response.text),
                    "has_corporate_linkage": "corporateLinkage" in hierarchy_response.text.lower()
                },
                "family_tree_api": {
                    "endpoint": f"{DNB_API_BASE}/v1/familytree/{test_duns}",
                    "status_code": family_tree_response.status_code,
                    "response_size": len(family_tree_response.text),
                    "has_family_members": "familyTreeMembers" in family_tree_response.text.lower()
                }
            }
            
    except Exception as e:
        return {
            "status": "error",
            "message": f"D&B Hierarchy API test failed: {str(e)}",
            "error_type": type(e).__name__
        }

# API Endpoints
@api_router.get("/")
async def root():
    return {"message": "D&B Business Partner Search API", "version": "1.0.0"}

@api_router.post("/login", response_model=Token)
async def login_for_access_token(login_data: LoginRequest):
    """Endpoint de connexion - retourne un JWT token"""
    try:
        if not authenticate_user(login_data.username, login_data.password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Nom d'utilisateur ou mot de passe incorrect",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        access_token_expires = timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": login_data.username}, expires_delta=access_token_expires
        )
        
        logger.info(f"User {login_data.username} logged in successfully")
        return {"access_token": access_token, "token_type": "bearer"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur interne du serveur"
        )

@api_router.get("/verify-token")
async def verify_token(current_user: str = Depends(get_current_user)):
    """Vérifier si le token est valide"""
    return {
        "valid": True,
        "username": current_user,
        "message": "Token valide"
    }

@api_router.get("/protected-status")
async def protected_status(current_user: str = Depends(get_current_user)):
    """Endpoint protégé pour vérifier l'authentification"""
    return {
        "message": "Accès autorisé à l'application D&B Business Partner Search",
        "user": current_user,
        "timestamp": datetime.utcnow().isoformat()
    }

# Endpoints protégés - Ajouter la dépendance d'authentification
@api_router.post("/unified-search")
async def unified_search(request: UnifiedSearchRequest, current_user: str = Depends(get_current_user)):
    """Recherche unifiée par différents critères"""
    try:
        # Vérifier qu'au moins un critère est fourni
        search_criteria = {
            "company_name": request.company_name,
            "duns": request.duns,
            "address": request.address,
            "street_address": request.street_address,
            "city": request.city,
            "state": request.state,
            "postal_code": request.postal_code,
            "country": request.country,
            "national_id": request.national_id,
            "phone": request.phone,
            "website": request.website,
            "email": request.email,
            "industry": request.industry,
            "business_type": request.business_type,
            "employee_count_min": request.employee_count_min,
            "employee_count_max": request.employee_count_max,
            "annual_revenue_min": request.annual_revenue_min,
            "annual_revenue_max": request.annual_revenue_max,
            "year_started_min": request.year_started_min,
            "year_started_max": request.year_started_max,
            "operating_status": request.operating_status,
            "legal_name": request.legal_name,
            "trade_name": request.trade_name,
            "stock_exchange": request.stock_exchange,
            
            # Mapping nouveaux champs vers anciens pour compatibilité
            "local_identifier": request.local_identifier,
            "continent": request.continent,
            "phone_fax": request.phone_fax,
            "has_phone": request.has_phone,
            "has_fax": request.has_fax
        }
        
        # Mapper les nouveaux champs vers les anciens pour la compatibilité
        if request.local_identifier and not search_criteria["national_id"]:
            search_criteria["national_id"] = request.local_identifier
            
        if request.phone_fax and not search_criteria["phone"]:
            search_criteria["phone"] = request.phone_fax
        
        # Filtrer les critères non vides
        active_criteria = {k: v for k, v in search_criteria.items() if v and v.strip()}
        
        if not active_criteria:
            raise HTTPException(status_code=400, detail="Au moins un critère de recherche est requis")
        
        logger.info(f"Unified search with criteria: {active_criteria}")
        
        # APPROCHE UNIFIÉE: Utiliser l'API D&B Match and Clean pour TOUTES les recherches
        logger.info(f"Using D&B Match and Clean API for all search types")
        
        # Essayer d'abord l'API D&B Match and Clean
        dnb_results = await try_dnb_match_and_clean(request)
        
        if dnb_results:
            logger.info(f"SUCCESS: D&B Match and Clean returned {len(dnb_results)} results")
            
            # Cache les résultats D&B dans MongoDB
            for result in dnb_results:
                try:
                    await db.companies.replace_one(
                        {"duns": result["duns"]}, 
                        result, 
                        upsert=True
                    )
                except Exception as e:
                    logger.error(f"Error caching D&B result: {str(e)}")
            
            return {"results": dnb_results}
        
        # Si l'API D&B ne retourne pas de résultats, utiliser les données mockées AVEC simulation Match and Clean
        logger.info("D&B API returned no results, using enhanced mock data with Match and Clean simulation")
        mock_results = create_mock_company_data(request)
        
        # Simuler les stratégies Match and Clean pour les données mockées
        for result in mock_results:
            result["search_criteria"] = active_criteria
            result["data_source"] = "Enhanced Mock Data (simulating D&B Match and Clean)"
            result["last_updated"] = datetime.now().isoformat()
            
            # Simuler la stratégie de recherche selon les critères utilisés
            search_strategy = "Unknown"
            confidence_code = 5
            
            if request.duns:
                search_strategy = "DUNS Exact Match"
                confidence_code = 10
            elif request.local_identifier or request.national_id:
                search_strategy = "Local Identifier Match"
                confidence_code = 9
            elif request.company_name and (request.address or request.city):
                search_strategy = "Company Name + Address Match"
                confidence_code = 7
            elif request.company_name:
                search_strategy = "Company Name Match"
                confidence_code = 6
            elif request.phone_fax or request.phone:
                search_strategy = "Phone/Contact Match"
                confidence_code = 8
            elif request.country or request.continent:
                search_strategy = "Geographic/Broad Match"
                confidence_code = 4
            
            # Ajouter les informations de ranking simulées
            result["search_strategy"] = search_strategy
            result["match_grade"] = confidence_code
            result["confidence_code"] = confidence_code
            result["ranking_info"] = {
                "match_grade": confidence_code,
                "confidence_code": confidence_code,
                "confidence_description": get_confidence_description(confidence_code),
                "match_quality": get_match_quality(confidence_code),
                "search_strategy": search_strategy,
                "is_high_confidence": confidence_code >= 8,
                "is_recommended": confidence_code >= 6,
                "grs_score": confidence_code
            }
        
        if mock_results:
            logger.info(f"SUCCESS: Enhanced mock data returned {len(mock_results)} results with simulated Match and Clean")
            return {"results": mock_results}
        
        # Aucun résultat trouvé
        logger.info("No results found in D&B API or mock data")
        return {"results": []}
        
        # Vérifier si nous avons des résultats mock
        if not mock_results:
            logger.info("No mock data matches found either")
            return SearchResult(
                results=[],
                total_count=0,
                search_query=f"No results found for criteria: {', '.join([f'{k}: {v}' for k, v in active_criteria.items()])}",
                search_criteria=active_criteria
            )
        
        # Ajouter des informations de ranking simulées aux données mock
        results_dict = []
        for i, company in enumerate(mock_results):
            # company est maintenant un dictionnaire au lieu d'un objet BusinessPartnerInfo
            # Simuler des scores de confiance basés sur la précision de la correspondance
            confidence_score = 10 if request.duns == company.get("duns") else (9 - i)  # Plus haut pour correspondance exacte
            match_grade = 95 if request.duns == company.get("duns") else (90 - i * 5)
            
            # Ajouter les informations de ranking
            company_dict = company.copy()  # company est déjà un dictionnaire
            company_dict.update({
                "match_grade": match_grade,
                "confidence_code": confidence_score,
                "ranking_info": {
                    "match_grade": match_grade,
                    "confidence_code": confidence_score,
                    "confidence_description": get_confidence_description(confidence_score),
                    "match_quality": get_match_quality(match_grade),
                    "is_high_confidence": confidence_score >= 8,
                    "is_recommended": confidence_score >= 6
                },
                "data_source": "Mock Data (avec ranking simulé)"
            })
            results_dict.append(company_dict)
        
        # Trier par ranking (confidence_code puis match_grade)
        results_dict.sort(key=lambda x: (x.get("confidence_code", 0), x.get("match_grade", 0)), reverse=True)
        
        # Créer une requête textuelle pour l'affichage
        query_parts = []
        for key, value in active_criteria.items():
            if value:
                query_parts.append(f"{key}: {value}")
        query_text = ", ".join(query_parts)
        
        return SearchResult(
            results=results_dict,
            total_count=len(results_dict),
            search_query=f"{query_text} (Source: Mock Data)",
            search_criteria=active_criteria
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in unified search: {str(e)}")
        raise HTTPException(status_code=500, detail="Search error")

@api_router.post("/company-profile-extended", response_model=ExtendedBusinessPartnerInfo)
async def get_extended_company_profile(request: DUNSRequest):
    """Get detailed company profile with ALL D&B Company Info L1 data"""
    try:
        logger.info(f"Extended company profile request for DUNS: {request.duns}")
        
        # Essayer l'API D&B en premier
        token = await get_cached_token()
        headers = {"Authorization": f"Bearer {token}"}
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(
                f"{DNB_API_BASE}/v1/data/duns/{request.duns}",
                headers=headers,
                params={"blockIDs": "companyinfo_L1_v1"}
            )
            
            if response.status_code == 200:
                data = response.json()
                
                # Parser avec toutes les données
                extended_partner = parse_complete_dnb_data(data, request.duns, {"duns": request.duns})
                
                # Cache le résultat étendu
                await db.extended_business_partners.update_one(
                    {"duns": request.duns},
                    {"$set": extended_partner.model_dump()},
                    upsert=True
                )
                
                logger.info(f"Successfully retrieved extended data for DUNS: {request.duns}")
                return extended_partner
            
            elif response.status_code == 404:
                raise HTTPException(status_code=404, detail=f"Company with DUNS {request.duns} not found")
            else:
                logger.error(f"D&B API request failed: {response.status_code} - {response.text}")
                raise HTTPException(status_code=response.status_code, detail="D&B API request failed")
                
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving extended company profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.post("/company-profile", response_model=BusinessPartnerInfo)
async def get_company_profile(request: DUNSRequest, current_user: str = Depends(get_current_user)):
    """Get detailed company profile by DUNS number"""
    try:
        # Utiliser la recherche unifiée
        unified_request = UnifiedSearchRequest(duns=request.duns)
        search_result = await unified_search(unified_request)
        
        if search_result.total_count == 0:
            raise HTTPException(status_code=404, detail=f"Company with DUNS {request.duns} not found")
        
        return BusinessPartnerInfo(**search_result.results[0])
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving company profile: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal server error")

@api_router.post("/company-search", response_model=SearchResult)
async def search_companies(request: CompanySearchRequest):
    """Search for companies by name (legacy endpoint)"""
    try:
        # Utiliser la recherche unifiée
        unified_request = UnifiedSearchRequest(
            company_name=request.name,
            country=request.country
        )
        return await unified_search(unified_request)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching companies: {str(e)}")
        raise HTTPException(status_code=500, detail="Search error")

@api_router.get("/cached-companies", response_model=List[BusinessPartnerInfo])
async def get_cached_companies():
    """Get all cached company profiles"""
    try:
        cached_companies = await db.business_partners.find().sort("last_updated", -1).to_list(100)
        return [BusinessPartnerInfo(**company) for company in cached_companies]
    except Exception as e:
        logger.error(f"Error retrieving cached companies: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving cached data")

@api_router.get("/cached-companies-extended", response_model=List[ExtendedBusinessPartnerInfo])
async def get_cached_extended_companies():
    """Get all cached extended company profiles"""
    try:
        cached_companies = await db.extended_business_partners.find().sort("last_updated", -1).to_list(100)
        return [ExtendedBusinessPartnerInfo(**company) for company in cached_companies]
    except Exception as e:
        logger.error(f"Error retrieving cached extended companies: {str(e)}")
        raise HTTPException(status_code=500, detail="Error retrieving cached extended data")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

    from fastapi.responses import JSONResponse

@app.get("/", tags=["Root"])
async def root():
    return JSONResponse({
        "message": "🚀 DunsHierarchy API is running!",
        "docs": "/docs",
        "health": "OK"
    })
