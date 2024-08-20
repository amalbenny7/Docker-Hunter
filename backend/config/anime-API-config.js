const ANIME_API_URL = "https://graphql.anilist.co";
const TIMEOUT_SEC = 10;
const ITEMS_PER_PAGE = 30;

const attributes = ` 
  id,
  seasonYear,
  title {
    romaji
    english
    native
    userPreferred
  }
  status,
  startDate {
    year
    month
    day
  },
  endDate {
    year
    month
    day
  },
  genres,
  coverImage {
    extraLarge
    large
    medium
    color
  },
  bannerImage,
  nextAiringEpisode {
    id,
    timeUntilAiring,
    episode
  },
  meanScore,
  averageScore,
  episodes,
  format,
  description,
`;

const castAttribute = `
characters(sort:ROLE){
  edges {
    node {
      name {
        full
      }
      image {
        large
        medium
      }
    }
    voiceActors(language:JAPANESE){
      id
      name {
        full
      }
      image {
        large
        medium
      },
      languageV2,
    }
  }
},
duration,
source,
favourites,
season,
meanScore,
averageScore,
studios {
  edges {
    node {
      id,
      name,
      isAnimationStudio
    }
  }
},
`;

const GET_ANIME_QUERY = `query($id: Int){
  Media(id: $id){
    ${attributes + castAttribute}
  }
}`;

const TRENDING_ANIMES_QUERY = `query($pageNo:Int, $itemsPerPage:Int){
    Page(page:$pageNo, perPage:$itemsPerPage){
      pageInfo {
        total
        perPage
        currentPage
        lastPage
        hasNextPage
      }
      media(sort:TRENDING_DESC, type:ANIME, genre_not_in:"hentai"){
        ${attributes}
      }
    }
  }`;

const UPCOMING_ANIMES_QUERY = `query ($pageNo:Int,$itemsPerPage:Int) {
    Page(page: $pageNo, perPage:$itemsPerPage) {
      pageInfo {
        total
        perPage
        currentPage
        lastPage
        hasNextPage
      }
      media(sort:POPULARITY_DESC, type:ANIME, status:NOT_YET_RELEASED, genre_not_in:"hentai"){
        ${attributes}
      }
    }
  }
  `;

module.exports = {
  UPCOMING_ANIMES_QUERY,
  TRENDING_ANIMES_QUERY,
  GET_ANIME_QUERY,
  ITEMS_PER_PAGE,
  TIMEOUT_SEC,
  ANIME_API_URL,
};
